using Radar.Core.Model;

namespace Radar.Core.Reporting;

public enum RemovalItemKind
{
    KillProcess = 0,
    RemovePersistence = 1,
    DeleteFile = 2,
    ReviewSibling = 3,
}

/// <summary>Um item do checklist de remoção. A execução fica com o usuário.</summary>
public sealed record RemovalItem
{
    public required RemovalItemKind Kind { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    /// <summary>Local exato para o botão "abrir local" (chave de registro, pasta, caminho da tarefa).</summary>
    public string? OpenLocation { get; init; }
}

/// <summary>
/// Plano de remoção assistida: para um processo marcado como suspeito, gera checklist com
/// tudo que a ferramenta sabe: persistências, arquivos criados, processos-irmãos da mesma linhagem.
/// </summary>
public static class RemovalPlanBuilder
{
    public static IReadOnlyList<RemovalItem> Build(
        ProcessExecution target,
        IReadOnlyCollection<PersistenceEntry> relatedPersistence,
        IReadOnlyCollection<FileActivity> filesCreated,
        IReadOnlyCollection<ProcessExecution> lineageSiblings)
    {
        var items = new List<RemovalItem>();

        if (target.IsAlive)
        {
            items.Add(new RemovalItem
            {
                Kind = RemovalItemKind.KillProcess,
                Title = $"Terminate the process {target.Binary.FileName} (PID {target.Pid})",
                Detail = "The process is still running. Terminate it before removing files to avoid re-creation.",
            });
        }

        foreach (var p in relatedPersistence.Where(p => p.RemovedUtc is null))
        {
            items.Add(new RemovalItem
            {
                Kind = RemovalItemKind.RemovePersistence,
                Title = $"Remove persistence: {p.Name} ({KindPt(p.Kind)})",
                Detail = $"Points to \"{p.Target}\". Installed/first seen on {p.FirstSeenUtc.ToLocalTime():dd/MM/yyyy HH:mm}." +
                         (p.InstallerExecutionId is not null ? " Installation correlated with an execution of this binary." : string.Empty),
                OpenLocation = p.Location,
            });
        }

        items.Add(new RemovalItem
        {
            Kind = RemovalItemKind.DeleteFile,
            Title = $"Evaluate removing the binary: {target.Binary.Path}",
            Detail = $"SHA-256 {target.Binary.Sha256 ?? "(not computed)"}. " +
                     "Consider submitting the hash to your antivirus before deleting (Radar preserves the dossier even without the file).",
            OpenLocation = Path.GetDirectoryName(target.Binary.Path),
        });

        foreach (var f in filesCreated.Where(f => f.Kind is FileEventKind.ExecutableDrop or FileEventKind.ArchiveStaging))
        {
            items.Add(new RemovalItem
            {
                Kind = RemovalItemKind.DeleteFile,
                Title = $"Evaluate a file created by this process: {Path.GetFileName(f.Path)}",
                Detail = $"Created on {f.TimestampUtc.ToLocalTime():dd/MM/yyyy HH:mm:ss} at \"{f.Path}\"" +
                         (f.Sha256 is { } h ? $" (SHA-256 {h})." : "."),
                OpenLocation = Path.GetDirectoryName(f.Path),
            });
        }

        foreach (var sibling in lineageSiblings.Where(s => s.ExecutionId != target.ExecutionId))
        {
            items.Add(new RemovalItem
            {
                Kind = RemovalItemKind.ReviewSibling,
                Title = $"Review a process from the same lineage: {sibling.Binary.FileName}",
                Detail = $"Ran on {sibling.CreatedUtc.ToLocalTime():dd/MM/yyyy HH:mm:ss} from \"{sibling.Binary.Path}\" " +
                         $"- part of the same chain of events.",
                OpenLocation = Path.GetDirectoryName(sibling.Binary.Path),
            });
        }

        return items;
    }

    private static string KindPt(PersistenceKind kind) => kind switch
    {
        PersistenceKind.RunKey => "Run key",
        PersistenceKind.RunOnceKey => "RunOnce key",
        PersistenceKind.StartupFolder => "Startup folder",
        PersistenceKind.ScheduledTask => "scheduled task",
        PersistenceKind.Service => "service",
        PersistenceKind.Ifeo => "IFEO",
        PersistenceKind.AppInitDll => "AppInit DLL",
        PersistenceKind.AppCertDll => "AppCert DLL",
        PersistenceKind.ShellExtension => "shell extension",
        PersistenceKind.WmiSubscription => "WMI subscription",
        PersistenceKind.LsaProvider => "LSA provider",
        PersistenceKind.Winlogon => "Winlogon",
        _ => kind.ToString(),
    };
}
