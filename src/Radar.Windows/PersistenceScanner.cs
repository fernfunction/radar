using System.Management;
using Microsoft.Win32;
using Radar.Core.Model;

namespace Radar.Windows;

/// <summary>
/// Varredura dos pontos de persistência: Run/RunOnce (HKCU/HKLM), pastas Startup,
/// tarefas agendadas, serviços, IFEO/AppInit/AppCertDLL, Winlogon, assinaturas WMI, LSA providers.
/// O diff temporal e a correlação com execuções acontecem no coletor/Core.
/// </summary>
public sealed class PersistenceScanner
{
    public IReadOnlyList<PersistenceEntry> ScanAll(DateTimeOffset nowUtc)
    {
        var entries = new List<PersistenceEntry>();
        SafeAdd(entries, () => ScanRunKeys(nowUtc));
        SafeAdd(entries, () => ScanStartupFolders(nowUtc));
        SafeAdd(entries, () => ScanScheduledTasks(nowUtc));
        SafeAdd(entries, () => ScanServices(nowUtc));
        SafeAdd(entries, () => ScanIfeo(nowUtc));
        SafeAdd(entries, () => ScanAppInitAndCert(nowUtc));
        SafeAdd(entries, () => ScanWinlogon(nowUtc));
        SafeAdd(entries, () => ScanWmiSubscriptions(nowUtc));
        SafeAdd(entries, () => ScanLsaProviders(nowUtc));
        return entries;
    }

    private static void SafeAdd(List<PersistenceEntry> target, Func<IEnumerable<PersistenceEntry>> scan)
    {
        try { target.AddRange(scan()); }
        catch { /* ponto inacessível sem elevação; degradação graciosa */ }
    }

    private static IEnumerable<PersistenceEntry> ScanRunKeys(DateTimeOffset now)
    {
        var locations = new (RegistryKey Root, string SubKey, PersistenceKind Kind)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceKind.RunKey),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceKind.RunOnceKey),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", PersistenceKind.RunKey),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceKind.RunOnceKey),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceKind.RunKey),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceKind.RunOnceKey),
        };

        foreach (var (root, subKey, kind) in locations)
        {
            using var key = root.OpenSubKey(subKey);
            if (key is null) continue;
            var location = $"{RootName(root)}\\{subKey}";
            foreach (var valueName in key.GetValueNames())
            {
                if (key.GetValue(valueName) is not string command || command.Length == 0) continue;
                yield return Make(kind, location, valueName, command, now);
            }
        }
    }

    private static IEnumerable<PersistenceEntry> ScanStartupFolders(DateTimeOffset now)
    {
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };
        foreach (var folder in folders.Where(f => !string.IsNullOrEmpty(f) && Directory.Exists(f)))
        {
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                var name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                yield return Make(PersistenceKind.StartupFolder, folder, name, file, now,
                    targetBinary: ResolveShortcut(file) ?? file);
            }
        }
    }

    private static string? ResolveShortcut(string path)
    {
        if (!path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType is null) return null;
            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic shortcut = shell.CreateShortcut(path);
            string target = shortcut.TargetPath;
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<PersistenceEntry> ScanScheduledTasks(DateTimeOffset now)
    {
        var results = new List<PersistenceEntry>();
        try
        {
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType is null) return results;
            dynamic scheduler = Activator.CreateInstance(schedulerType)!;
            scheduler.Connect();
            CollectTasksRecursive(scheduler.GetFolder("\\"), results, now);
        }
        catch
        {
            // Agendador indisponível; segue sem tarefas
        }
        return results;
    }

    private static void CollectTasksRecursive(dynamic folder, List<PersistenceEntry> results, DateTimeOffset now)
    {
        foreach (dynamic task in folder.GetTasks(1)) // 1 = TASK_ENUM_HIDDEN
        {
            try
            {
                string path = task.Path;
                dynamic definition = task.Definition;
                string? author = null;
                try { author = definition.RegistrationInfo.Author; } catch { }
                DateTimeOffset? registered = null;
                try
                {
                    string date = definition.RegistrationInfo.Date;
                    if (!string.IsNullOrWhiteSpace(date) && DateTimeOffset.TryParse(date, out var d)) registered = d;
                }
                catch { }

                var actions = new List<string>();
                string? firstBinary = null;
                try
                {
                    foreach (dynamic action in definition.Actions)
                    {
                        try
                        {
                            if ((int)action.Type == 0) // TASK_ACTION_EXEC
                            {
                                string exe = action.Path ?? string.Empty;
                                string args = string.Empty;
                                try { args = action.Arguments ?? string.Empty; } catch { }
                                actions.Add($"{exe} {args}".Trim());
                                firstBinary ??= Environment.ExpandEnvironmentVariables(exe.Trim('"'));
                            }
                            else
                            {
                                actions.Add($"(action type {(int)action.Type})");
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                if (actions.Count == 0) continue;

                results.Add(new PersistenceEntry
                {
                    Id = PersistenceDiffer.StableId(PersistenceKind.ScheduledTask, "TaskScheduler", path),
                    Kind = PersistenceKind.ScheduledTask,
                    Location = path,
                    Name = path[(path.LastIndexOf('\\') + 1)..],
                    Target = string.Join(" | ", actions),
                    TargetBinaryPath = firstBinary,
                    FirstSeenUtc = registered ?? now,
                    LastSeenUtc = now,
                    Author = author,
                    TriggerDescription = DescribeTriggers(definition),
                });
            }
            catch { }
        }

        try
        {
            foreach (dynamic sub in folder.GetFolders(0))
                CollectTasksRecursive(sub, results, now);
        }
        catch { }
    }

    private static string? DescribeTriggers(dynamic definition)
    {
        try
        {
            var kinds = new List<string>();
            foreach (dynamic trigger in definition.Triggers)
            {
                kinds.Add((int)trigger.Type switch
                {
                    1 => "once", 2 => "daily", 3 => "weekly", 4 => "monthly",
                    8 => "at system startup", 9 => "at logon", 0 => "on event",
                    6 => "at task registration", 11 => "on session connect",
                    var t => $"type {t}",
                });
            }
            return kinds.Count > 0 ? string.Join(", ", kinds) : null;
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<PersistenceEntry> ScanServices(DateTimeOffset now)
    {
        using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (servicesKey is null) yield break;

        foreach (var serviceName in servicesKey.GetSubKeyNames())
        {
            using var svc = servicesKey.OpenSubKey(serviceName);
            if (svc is null) continue;
            // Start: 0/1 drivers de boot, 2 automático, 3 manual, 4 desabilitado. Foco em auto-start
            if (svc.GetValue("Start") is not int start || start > 2) continue;
            if (svc.GetValue("ImagePath") is not string imagePath || imagePath.Length == 0) continue;
            if (svc.GetValue("Type") is int type && (type & 0x3) != 0) continue; // exclui drivers de kernel/fs

            yield return Make(PersistenceKind.Service,
                $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}", serviceName,
                Environment.ExpandEnvironmentVariables(imagePath), now);
        }
    }

    private static IEnumerable<PersistenceEntry> ScanIfeo(DateTimeOffset now)
    {
        const string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        using var ifeo = Registry.LocalMachine.OpenSubKey(ifeoPath);
        if (ifeo is null) yield break;
        foreach (var exeName in ifeo.GetSubKeyNames())
        {
            using var sub = ifeo.OpenSubKey(exeName);
            if (sub?.GetValue("Debugger") is string debugger && debugger.Length > 0)
            {
                yield return Make(PersistenceKind.Ifeo, $@"HKLM\{ifeoPath}\{exeName}", exeName, debugger, now);
            }
        }
    }

    private static IEnumerable<PersistenceEntry> ScanAppInitAndCert(DateTimeOffset now)
    {
        const string windowsKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        using var win = Registry.LocalMachine.OpenSubKey(windowsKey);
        if (win?.GetValue("AppInit_DLLs") is string appInit && appInit.Trim().Length > 0)
            yield return Make(PersistenceKind.AppInitDll, $@"HKLM\{windowsKey}", "AppInit_DLLs", appInit, now);

        const string appCertKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";
        using var appCert = Registry.LocalMachine.OpenSubKey(appCertKey);
        if (appCert is not null)
        {
            foreach (var name in appCert.GetValueNames())
            {
                if (appCert.GetValue(name) is string dll && dll.Length > 0)
                    yield return Make(PersistenceKind.AppCertDll, $@"HKLM\{appCertKey}", name, dll, now);
            }
        }
    }

    private static IEnumerable<PersistenceEntry> ScanWinlogon(DateTimeOffset now)
    {
        const string winlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        using var key = Registry.LocalMachine.OpenSubKey(winlogonKey);
        if (key is null) yield break;

        if (key.GetValue("Shell") is string shell &&
            !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            yield return Make(PersistenceKind.Winlogon, $@"HKLM\{winlogonKey}", "Shell", shell, now);

        if (key.GetValue("Userinit") is string userinit)
        {
            var normalized = userinit.TrimEnd(',').Trim();
            if (!normalized.EndsWith(@"\userinit.exe", StringComparison.OrdinalIgnoreCase))
                yield return Make(PersistenceKind.Winlogon, $@"HKLM\{winlogonKey}", "Userinit", userinit, now);
        }
    }

    private static IEnumerable<PersistenceEntry> ScanWmiSubscriptions(DateTimeOffset now)
    {
        var results = new List<PersistenceEntry>();
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();

        var consumers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var searcher = new ManagementObjectSearcher(scope,
                   new ObjectQuery("SELECT * FROM CommandLineEventConsumer")))
        {
            foreach (var consumer in searcher.Get())
            {
                var name = consumer["Name"]?.ToString() ?? "?";
                var cmd = consumer["CommandLineTemplate"]?.ToString() ?? consumer["ExecutablePath"]?.ToString() ?? string.Empty;
                consumers[name] = cmd;
            }
        }
        using (var searcher = new ManagementObjectSearcher(scope,
                   new ObjectQuery("SELECT * FROM ActiveScriptEventConsumer")))
        {
            foreach (var consumer in searcher.Get())
            {
                var name = consumer["Name"]?.ToString() ?? "?";
                consumers[name] = $"(script {consumer["ScriptingEngine"]}) {consumer["ScriptFileName"] ?? "inline"}";
            }
        }

        using (var searcher = new ManagementObjectSearcher(scope,
                   new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
        {
            foreach (var binding in searcher.Get())
            {
                var consumerRef = binding["Consumer"]?.ToString() ?? string.Empty;
                var filterRef = binding["Filter"]?.ToString() ?? string.Empty;
                var consumerName = ExtractWmiName(consumerRef);
                var command = consumers.GetValueOrDefault(consumerName, consumerRef);
                results.Add(new PersistenceEntry
                {
                    Id = PersistenceDiffer.StableId(PersistenceKind.WmiSubscription, @"root\subscription", $"{filterRef}->{consumerRef}"),
                    Kind = PersistenceKind.WmiSubscription,
                    Location = @"root\subscription (__FilterToConsumerBinding)",
                    Name = consumerName,
                    Target = command,
                    TargetBinaryPath = ExtractBinaryPath(command),
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                    TriggerDescription = $"WMI filter: {ExtractWmiName(filterRef)}",
                });
            }
        }
        return results;
    }

    private static string ExtractWmiName(string reference)
    {
        var idx = reference.IndexOf("Name=\"", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return reference;
        var start = idx + 6;
        var end = reference.IndexOf('"', start);
        return end > start ? reference[start..end] : reference;
    }

    private static IEnumerable<PersistenceEntry> ScanLsaProviders(DateTimeOffset now)
    {
        const string lsaKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
        using var key = Registry.LocalMachine.OpenSubKey(lsaKey);
        if (key is null) yield break;

        foreach (var valueName in new[] { "Security Packages", "Authentication Packages", "Notification Packages" })
        {
            if (key.GetValue(valueName) is string[] packages)
            {
                var nonDefault = packages.Where(p =>
                    p.Length > 0 && p != "\"\"" &&
                    !DefaultLsaPackages.Contains(p)).ToList();
                if (nonDefault.Count > 0)
                    yield return Make(PersistenceKind.LsaProvider, $@"HKLM\{lsaKey}", valueName,
                        string.Join(", ", nonDefault), now);
            }
        }
    }

    private static readonly HashSet<string> DefaultLsaPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "livessp", "scecli", "rassfm",
    };

    private static PersistenceEntry Make(PersistenceKind kind, string location, string name, string target,
        DateTimeOffset now, string? targetBinary = null) => new()
    {
        Id = PersistenceDiffer.StableId(kind, location, name),
        Kind = kind,
        Location = location,
        Name = name,
        Target = target,
        TargetBinaryPath = targetBinary ?? ExtractBinaryPath(target),
        FirstSeenUtc = now,
        LastSeenUtc = now,
    };

    /// <summary>Extrai o caminho do binário de uma linha de comando ("C:\x\a.exe" /args → C:\x\a.exe).</summary>
    public static string? ExtractBinaryPath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        if (expanded.StartsWith('"'))
        {
            var end = expanded.IndexOf('"', 1);
            return end > 1 ? expanded[1..end] : null;
        }
        // svchost -k netsvcs → caminho até o primeiro espaço, tentando completar .exe
        var firstSpace = expanded.IndexOf(' ');
        var candidate = firstSpace > 0 ? expanded[..firstSpace] : expanded;
        if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || firstSpace < 0)
            return candidate;
        // caminho com espaços sem aspas: procura ".exe" no texto
        var exeIdx = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exeIdx > 0 ? expanded[..(exeIdx + 4)] : candidate;
    }

    private static string RootName(RegistryKey root) =>
        root.Name.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.Ordinal) ? "HKLM" :
        root.Name.StartsWith("HKEY_CURRENT_USER", StringComparison.Ordinal) ? "HKCU" : root.Name;
}
