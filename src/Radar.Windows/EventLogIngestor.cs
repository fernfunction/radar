using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;

namespace Radar.Windows;

/// <summary>Evento 4688 normalizado (criação de processo via auditoria do Windows).</summary>
public sealed record AuditProcessEvent(
    DateTimeOffset TimestampUtc,
    int Pid,
    string ImagePath,
    string? CommandLine,
    int ParentPid,
    string? ParentImage,
    string? UserName);

/// <summary>
/// Fallback/retroatividade via Security Event Log 4688/4689: cobre o período em que o
/// coletor ETW não estava rodando, quando a auditoria de criação de processos estiver habilitada.
/// A aplicação pode oferecer habilitá-la pelo assistente de primeiro uso.
/// </summary>
public static class EventLogIngestor
{
    /// <summary>A auditoria de criação de processos com linha de comando está habilitada?</summary>
    public static bool IsProcessAuditingEnabled()
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4688)]]")
            {
                ReverseDirection = true,
            };
            using var reader = new EventLogReader(query);
            return reader.ReadEvent(TimeSpan.FromMilliseconds(800)) is not null;
        }
        catch
        {
            return false; // sem privilégio para ler Security
        }
    }

    /// <summary>
    /// Habilita a auditoria de criação de processos + inclusão de linha de comando.
    /// Requer elevação; GUID da subcategoria independe de idioma.
    /// </summary>
    public static bool TryEnableProcessAuditing(out string message)
    {
        try
        {
            var audit = Run("auditpol.exe",
                "/set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable");
            var cmdline = Run("reg.exe",
                @"add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit " +
                "/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f");
            message = audit && cmdline
                ? "Process-creation auditing enabled (event 4688 with command line)."
                : "Failed to enable auditing - run as administrator.";
            return audit && cmdline;
        }
        catch (Exception ex)
        {
            message = $"Error enabling auditing: {ex.Message}";
            return false;
        }
    }

    /// <summary>Lê eventos 4688 do período (retroatividade limitada ao que o log preservou).</summary>
    public static IReadOnlyList<AuditProcessEvent> ReadProcessCreations(DateTimeOffset fromUtc, int maxEvents = 5000)
    {
        var results = new List<AuditProcessEvent>();
        try
        {
            var time = fromUtc.UtcDateTime.ToString("o");
            var query = new EventLogQuery("Security", PathType.LogName,
                $"*[System[(EventID=4688) and TimeCreated[@SystemTime >= '{time}']]]");
            using var reader = new EventLogReader(query);
            while (reader.ReadEvent() is { } record && results.Count < maxEvents)
            {
                using (record)
                {
                    try
                    {
                        var xml = new System.Xml.XmlDocument();
                        xml.LoadXml(record.ToXml());
                        var ns = new System.Xml.XmlNamespaceManager(xml.NameTable);
                        ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");

                        string? Get(string name) =>
                            xml.SelectSingleNode($"//e:Data[@Name='{name}']", ns)?.InnerText;

                        var image = Get("NewProcessName");
                        if (image is null) continue;
                        results.Add(new AuditProcessEvent(
                            record.TimeCreated is { } t ? new DateTimeOffset(t.ToUniversalTime()) : DateTimeOffset.UtcNow,
                            ParseHexOrInt(Get("NewProcessId")),
                            image,
                            Get("CommandLine"),
                            ParseHexOrInt(Get("ProcessId")),
                            Get("ParentProcessName"),
                            Get("SubjectUserName")));
                    }
                    catch { }
                }
            }
        }
        catch
        {
            // Security log inacessível sem elevação; degradação graciosa
        }
        return results;
    }

    private static int ParseHexOrInt(string? value)
    {
        if (string.IsNullOrEmpty(value)) return 0;
        return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? Convert.ToInt32(value, 16)
            : int.TryParse(value, out var i) ? i : 0;
    }

    private static bool Run(string file, string args)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = file,
            Arguments = args,
            CreateNoWindow = true,
            UseShellExecute = false,
        });
        proc!.WaitForExit(15000);
        return proc.ExitCode == 0;
    }
}
