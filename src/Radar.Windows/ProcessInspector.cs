using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Radar.Core.Model;

namespace Radar.Windows;

/// <summary>
/// Contexto de segurança de processos vivos: usuário/conta do token, nível de
/// integridade, elevação, sessão, janela visível, e detecção de Protected Process (PPL).
/// Consultado no momento da criação; o processo pode morrer logo depois.
/// </summary>
public static class ProcessInspector
{
    public static SecurityContext Inspect(int pid)
    {
        IntPtr hProcess = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        try
        {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
                return new SecurityContext { SessionId = SessionIdOf(pid) };

            string? userName = null, userSid = null;
            var integrity = IntegrityLevel.Unknown;
            bool elevated = false;

            if (OpenProcessToken(hProcess, TOKEN_QUERY, out hToken))
            {
                (userName, userSid) = ReadTokenUser(hToken);
                integrity = ReadIntegrityLevel(hToken);
                elevated = ReadElevation(hToken);
            }

            return new SecurityContext
            {
                UserName = userName,
                UserSid = userSid,
                AccountKind = ClassifyAccount(userSid, userName),
                IntegrityLevel = integrity,
                Elevated = elevated,
                SessionId = SessionIdOf(pid),
                HasVisibleWindow = HasVisibleWindow(pid),
            };
        }
        catch
        {
            return new SecurityContext { SessionId = SessionIdOf(pid) };
        }
        finally
        {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
    }

    /// <summary>Protected Process / PPL: excluído por padrão, fora do alcance do usuário.</summary>
    public static bool IsProtectedProcess(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return false;
        try
        {
            var info = new PROCESS_PROTECTION_LEVEL_INFORMATION { ProtectionLevel = PROTECTION_LEVEL_NONE };
            if (GetProcessInformation(hProcess, ProcessProtectionLevelInfo, ref info,
                    (uint)Marshal.SizeOf<PROCESS_PROTECTION_LEVEL_INFORMATION>()))
            {
                return info.ProtectionLevel != PROTECTION_LEVEL_NONE;
            }
            return false;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    public static string? GetImagePath(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return null;
        try
        {
            var capacity = 1024;
            var sb = new System.Text.StringBuilder(capacity);
            return QueryFullProcessImageName(hProcess, 0, sb, ref capacity) ? sb.ToString() : null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>SID da conta → classificação "quem".</summary>
    public static AccountKind ClassifyAccount(string? sid, string? userName)
    {
        switch (sid)
        {
            case "S-1-5-18": return AccountKind.System;
            case "S-1-5-19": return AccountKind.LocalService;
            case "S-1-5-20": return AccountKind.NetworkService;
            case null: return AccountKind.Unknown;
        }

        try
        {
            using var current = WindowsIdentity.GetCurrent();
            if (current.User?.Value is { } currentSid)
            {
                return string.Equals(currentSid, sid, StringComparison.OrdinalIgnoreCase)
                    ? AccountKind.InteractiveUser
                    : AccountKind.OtherLocalUser;
            }
        }
        catch { }
        return AccountKind.Unknown;
    }

    private static int SessionIdOf(int pid)
    {
        return ProcessIdToSessionId((uint)pid, out var session) ? (int)session : 0;
    }

    private static (string? Name, string? Sid) ReadTokenUser(IntPtr hToken)
    {
        GetTokenInformation(hToken, TokenUser, IntPtr.Zero, 0, out var size);
        if (size == 0) return (null, null);
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!GetTokenInformation(hToken, TokenUser, buffer, size, out _)) return (null, null);
            var sidPtr = Marshal.ReadIntPtr(buffer); // TOKEN_USER.User.Sid
            var sid = new SecurityIdentifier(sidPtr);
            string? name = null;
            try
            {
                name = sid.Translate(typeof(NTAccount)).Value;
            }
            catch { /* SID sem conta resolvível */ }
            return (name, sid.Value);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntegrityLevel ReadIntegrityLevel(IntPtr hToken)
    {
        GetTokenInformation(hToken, TokenIntegrityLevel, IntPtr.Zero, 0, out var size);
        if (size == 0) return IntegrityLevel.Unknown;
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!GetTokenInformation(hToken, TokenIntegrityLevel, buffer, size, out _))
                return IntegrityLevel.Unknown;
            var sidPtr = Marshal.ReadIntPtr(buffer);
            var subAuthorityCount = Marshal.ReadByte(GetSidSubAuthorityCount(sidPtr));
            var rid = Marshal.ReadInt32(GetSidSubAuthority(sidPtr, subAuthorityCount - 1));
            return rid switch
            {
                < 0x1000 => IntegrityLevel.Untrusted,
                < 0x2000 => IntegrityLevel.Low,
                < 0x3000 => IntegrityLevel.Medium,
                < 0x4000 => IntegrityLevel.High,
                _ => IntegrityLevel.System,
            };
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool ReadElevation(IntPtr hToken)
    {
        var buffer = Marshal.AllocHGlobal(4);
        try
        {
            return GetTokenInformation(hToken, TokenElevation, buffer, 4, out _) &&
                   Marshal.ReadInt32(buffer) != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Tem janela visível, ou roda oculto? Custo O(janelas); usar com parcimônia.</summary>
    public static bool? HasVisibleWindow(int pid)
    {
        try
        {
            bool found = false;
            EnumWindows((hwnd, _) =>
            {
                GetWindowThreadProcessId(hwnd, out var windowPid);
                if (windowPid == (uint)pid && IsWindowVisible(hwnd))
                {
                    found = true;
                    return false;
                }
                return true;
            }, IntPtr.Zero);
            return found;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Pai DECLARADO no PEB (InheritedFromUniqueProcessId). O ETW entrega o criador REAL;
    /// divergência entre os dois = parent PID spoofing.
    /// </summary>
    public static int? GetDeclaredParentPid(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return null;
        try
        {
            var pbi = new PROCESS_BASIC_INFORMATION();
            var status = NtQueryInformationProcess(hProcess, 0, ref pbi,
                (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            return status == 0 ? (int)pbi.InheritedFromUniqueProcessId : null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    public static bool IsCurrentProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;
    private const int TokenElevation = 20;
    private const int TokenIntegrityLevel = 25;
    private const int ProcessProtectionLevelInfo = 7;
    private const uint PROTECTION_LEVEL_NONE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_PROTECTION_LEVEL_INFORMATION
    {
        public uint ProtectionLevel;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessInformation(IntPtr hProcess, int processInformationClass,
        ref PROCESS_PROTECTION_LEVEL_INFORMATION processInformation, uint processInformationSize);

    [DllImport("kernel32.dll")]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags,
        System.Text.StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);
}
