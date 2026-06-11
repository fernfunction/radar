using System.Management;
using Radar.Core.Analysis;

namespace Radar.Windows;

/// <summary>
/// Resolve pistas de origem do disparo consultando o sistema vivo: qual serviço roda
/// naquele PID, qual tarefa agendada está em execução, qual run key aponta para o binário.
/// Melhor esforço, chamado no momento da criação do processo, antes que o contexto morra.
/// </summary>
public sealed class OriginResolver
{
    /// <summary>Nome do serviço hospedado no PID (via SCM/WMI), para pais services.exe/svchost.</summary>
    public string? ResolveServiceByPid(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name, DisplayName FROM Win32_Service WHERE ProcessId = {pid}");
            foreach (var svc in searcher.Get())
            {
                var name = svc["Name"]?.ToString();
                var display = svc["DisplayName"]?.ToString();
                return display is { Length: > 0 } && display != name ? $"{name} ({display})" : name;
            }
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Tarefa agendada atualmente em execução cujo PID do processo da ação corresponde.
    /// Resolução do nome da tarefa para a atribuição "Disparado pelo Agendador".
    /// </summary>
    public string? ResolveRunningTaskByPid(int pid)
    {
        try
        {
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType is null) return null;
            dynamic scheduler = Activator.CreateInstance(schedulerType)!;
            scheduler.Connect();
            dynamic running = scheduler.GetRunningTasks(1); // 1 = TASK_ENUM_HIDDEN
            foreach (dynamic task in running)
            {
                try
                {
                    if ((int)task.EnginePID == pid) return task.Path;
                }
                catch { }
            }
        }
        catch { }
        return null;
    }

    /// <summary>Run key/Startup que aponta para este binário (correlação com a varredura local).</summary>
    public static (string Name, DateTimeOffset? InstalledUtc)? FindRunKeyFor(
        string imagePath, IReadOnlyCollection<Core.Model.PersistenceEntry> knownPersistence)
    {
        foreach (var entry in knownPersistence)
        {
            if (entry.Kind is not (Core.Model.PersistenceKind.RunKey or Core.Model.PersistenceKind.RunOnceKey
                or Core.Model.PersistenceKind.StartupFolder)) continue;
            if (entry.TargetBinaryPath is { } target &&
                target.Equals(imagePath, StringComparison.OrdinalIgnoreCase))
            {
                return ($"{entry.Location}\\{entry.Name}", entry.FirstSeenUtc);
            }
        }
        return null;
    }

    /// <summary>Extrai o arquivo de script da linha de comando de um host (wscript x.vbs → x.vbs).</summary>
    public static string? ExtractScriptFile(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        foreach (var ext in new[] { ".vbs", ".js", ".jse", ".vbe", ".wsf", ".hta", ".ps1" })
        {
            var idx = commandLine.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var end = idx + ext.Length;
            var start = commandLine.LastIndexOfAny(['"', ' ', '\t'], idx);
            return commandLine[(start + 1)..end];
        }
        return null;
    }

    public OriginHints BuildHints(int pid, string? creatorImage, string? commandLine, bool parentDead,
        IReadOnlyCollection<Core.Model.PersistenceEntry> knownPersistence, string imagePath)
    {
        var creatorName = creatorImage is null ? null : Path.GetFileName(creatorImage).ToLowerInvariant();
        string? serviceName = null;
        string? taskName = null;

        if (creatorName is "services.exe" or "svchost.exe")
            serviceName = ResolveServiceByPid(pid);
        if (serviceName is null && creatorName is "svchost.exe" or "taskhostw.exe" or "taskeng.exe")
            taskName = ResolveRunningTaskByPid(pid);

        var runKey = FindRunKeyFor(imagePath, knownPersistence);

        return new OriginHints
        {
            ServiceName = serviceName,
            ScheduledTaskName = taskName,
            RunKeyName = runKey?.Name,
            RunKeyInstalledUtc = runKey?.InstalledUtc,
            ParentDiedBeforeChild = parentDead,
            ScriptFile = ExtractScriptFile(commandLine),
        };
    }
}
