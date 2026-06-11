namespace Radar.Core.Model;

/// <summary>Entrada de ponto de persistência (autoruns) com contexto.</summary>
public sealed record PersistenceEntry
{
    public required string Id { get; init; }
    public required PersistenceKind Kind { get; init; }
    /// <summary>Localização exata (chave de registro, caminho da tarefa, nome do serviço).</summary>
    public required string Location { get; init; }
    public required string Name { get; init; }
    /// <summary>Comando/binário alvo.</summary>
    public required string Target { get; init; }
    /// <summary>Caminho do binário extraído do alvo (para avaliação de assinatura/masquerading).</summary>
    public string? TargetBinaryPath { get; init; }
    public DateTimeOffset FirstSeenUtc { get; init; }
    public DateTimeOffset LastSeenUtc { get; init; }
    public DateTimeOffset? RemovedUtc { get; init; }
    /// <summary>Execução que instalou a persistência, quando correlacionável pela linhagem de eventos.</summary>
    public Guid? InstallerExecutionId { get; init; }
    public SignatureInfo Signature { get; init; } = SignatureInfo.Unverified;
    public string? Author { get; init; }
    public string? TriggerDescription { get; init; }
}

/// <summary>Resultado do diff temporal entre varreduras.</summary>
public sealed record PersistenceDiff
{
    public IReadOnlyList<PersistenceEntry> Added { get; init; } = [];
    public IReadOnlyList<(PersistenceEntry Before, PersistenceEntry After)> Changed { get; init; } = [];
    public IReadOnlyList<PersistenceEntry> Removed { get; init; } = [];
    public DateTimeOffset ScanUtc { get; init; }

    public bool HasChanges => Added.Count > 0 || Changed.Count > 0 || Removed.Count > 0;
}

public static class PersistenceDiffer
{
    /// <summary>Compara duas varreduras pelo Id estável (kind+location+name).</summary>
    public static PersistenceDiff Diff(
        IReadOnlyCollection<PersistenceEntry> previous,
        IReadOnlyCollection<PersistenceEntry> current,
        DateTimeOffset scanUtc)
    {
        var prevById = previous.ToDictionary(p => p.Id, StringComparer.OrdinalIgnoreCase);
        var currById = current.ToDictionary(p => p.Id, StringComparer.OrdinalIgnoreCase);

        var added = new List<PersistenceEntry>();
        var changed = new List<(PersistenceEntry, PersistenceEntry)>();
        foreach (var entry in current)
        {
            if (!prevById.TryGetValue(entry.Id, out var before))
            {
                added.Add(entry);
            }
            else if (!string.Equals(before.Target, entry.Target, StringComparison.OrdinalIgnoreCase))
            {
                changed.Add((before, entry));
            }
        }

        var removed = previous.Where(p => !currById.ContainsKey(p.Id)).ToList();
        return new PersistenceDiff { Added = added, Changed = changed, Removed = removed, ScanUtc = scanUtc };
    }

    public static string StableId(PersistenceKind kind, string location, string name) =>
        $"{kind}|{location}|{name}".ToLowerInvariant();
}
