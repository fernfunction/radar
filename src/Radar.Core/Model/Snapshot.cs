namespace Radar.Core.Model;

/// <summary>
/// Snapshot do estado da máquina para comparação: binários conhecidos, persistências,
/// destinos. Compara dois momentos da máquina.
/// </summary>
public sealed record MachineSnapshot
{
    public required DateTimeOffset TakenUtc { get; init; }
    public string? Label { get; init; }
    /// <summary>hash → caminho representativo.</summary>
    public Dictionary<string, string> KnownBinaries { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> PersistenceIds { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> NetworkDestinations { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed record SnapshotComparison
{
    public required MachineSnapshot Before { get; init; }
    public required MachineSnapshot After { get; init; }
    public IReadOnlyList<string> NewBinaries { get; init; } = [];
    public IReadOnlyList<string> RemovedBinaries { get; init; } = [];
    public IReadOnlyList<string> NewPersistences { get; init; } = [];
    public IReadOnlyList<string> RemovedPersistences { get; init; } = [];
    public IReadOnlyList<string> NewDestinations { get; init; } = [];

    public bool HasChanges => NewBinaries.Count + RemovedBinaries.Count + NewPersistences.Count +
                              RemovedPersistences.Count + NewDestinations.Count > 0;

    public static SnapshotComparison Compare(MachineSnapshot before, MachineSnapshot after) => new()
    {
        Before = before,
        After = after,
        NewBinaries = after.KnownBinaries.Keys.Except(before.KnownBinaries.Keys, StringComparer.OrdinalIgnoreCase)
            .Select(h => $"{after.KnownBinaries[h]} ({Short(h)})").ToList(),
        RemovedBinaries = before.KnownBinaries.Keys.Except(after.KnownBinaries.Keys, StringComparer.OrdinalIgnoreCase)
            .Select(h => $"{before.KnownBinaries[h]} ({Short(h)})").ToList(),
        NewPersistences = after.PersistenceIds.Except(before.PersistenceIds, StringComparer.OrdinalIgnoreCase).ToList(),
        RemovedPersistences = before.PersistenceIds.Except(after.PersistenceIds, StringComparer.OrdinalIgnoreCase).ToList(),
        NewDestinations = after.NetworkDestinations.Except(before.NetworkDestinations, StringComparer.OrdinalIgnoreCase).ToList(),
    };

    private static string Short(string hash) => hash.Length > 12 ? hash[..12] + "…" : hash;
}
