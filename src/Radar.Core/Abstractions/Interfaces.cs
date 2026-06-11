using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Core.Abstractions;

/// <summary>Relógio injetável (testabilidade dos analisadores temporais).</summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public static SystemClock Instance { get; } = new();
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>Filtros combináveis das vistas.</summary>
public sealed record ExecutionQuery
{
    public DateTimeOffset? FromUtc { get; init; }
    public DateTimeOffset? ToUtc { get; init; }
    public string? UserName { get; init; }
    public int? MinScore { get; init; }
    public SignatureStatus? SignatureStatus { get; init; }
    public bool? HasNetworkActivity { get; init; }
    public string? PathPrefix { get; init; }
    /// <summary>Busca por nome, caminho, hash, domínio, IP, emissor, usuário.</summary>
    public string? SearchText { get; init; }
    public bool OnlyShortLived { get; init; }
    public int Limit { get; init; } = 500;
}

/// <summary>
/// Contrato do banco histórico: implementado por Radar.Data sobre SQLite.
/// Escrito pelo coletor, lido pela UI. A UI pode abrir e fechar sem interromper a coleta.
/// </summary>
public interface IEventStore
{
    void UpsertExecution(ProcessExecution execution);
    ProcessExecution? GetExecution(Guid executionId);
    IReadOnlyList<ProcessExecution> QueryExecutions(ExecutionQuery query);
    IReadOnlyList<ProcessExecution> GetExecutionsForBinary(string sha256, int limit = 100);
    IReadOnlyList<ProcessExecution> GetChildren(Guid executionId);
    int CountPriorRuns(string sha256, DateTimeOffset beforeUtc);
    string? GetLastHashForPath(string path);

    void AddNetworkConnection(NetworkConnection connection);
    void AddDnsQuery(DnsQuery query);
    void AddFileActivity(FileActivity activity);
    void AddModuleLoad(ModuleLoad moduleLoad);
    void AddResourceSample(ResourceSample sample);
    void AddSystemMarker(SystemMarker marker);
    IReadOnlyList<NetworkConnection> GetConnections(Guid executionId);
    IReadOnlyList<DnsQuery> GetDnsQueries(Guid executionId);
    IReadOnlyList<FileActivity> GetFileActivities(Guid executionId);
    IReadOnlyList<ModuleLoad> GetModuleLoads(Guid executionId);
    IReadOnlyList<ResourceSample> GetResourceSamples(Guid executionId);

    void AddTimelineEvent(TimelineEvent evt);
    IReadOnlyList<TimelineEvent> GetTimeline(DateTimeOffset fromUtc, DateTimeOffset toUtc, int minScore = 0);

    void UpsertPersistenceEntry(PersistenceEntry entry);
    void MarkPersistenceRemoved(string id, DateTimeOffset whenUtc);
    IReadOnlyList<PersistenceEntry> GetPersistenceEntries(bool includeRemoved = false);
    IReadOnlyList<PersistenceEntry> GetPersistenceForTarget(string binaryPathOrHash);

    IReadOnlyList<Filtering.TrustListEntry> GetTrustList();
    void AddTrustListEntry(Filtering.TrustListEntry entry);
    void RemoveTrustListEntry(string sha256);
    void SetVerdict(Guid executionId, UserVerdict verdict, string? notes);

    BaselineState LoadBaseline();
    void SaveBaseline(BaselineState state);

    void SaveSnapshot(MachineSnapshot snapshot);
    IReadOnlyList<MachineSnapshot> GetSnapshots();

    // Retenção: expurga eventos brutos antigos transformando-os em resumos estatísticos.
    RetentionResult PurgeAndSummarize(DateTimeOffset cutoffUtc, long maxDatabaseBytes);

    StoreStats GetStats();
}

public sealed record RetentionResult(int ExecutionsSummarized, int EventsPurged, long DatabaseBytes);

public sealed record StoreStats(long DatabaseBytes, int ExecutionCount, int EventCount,
    DateTimeOffset? OldestEventUtc, DateTimeOffset? NewestEventUtc);

/// <summary>Estado vivo da coleta exposto à UI/bandeja.</summary>
public sealed record CollectorHealth
{
    public bool Running { get; init; }
    public bool Paused { get; init; }
    public bool Elevated { get; init; }
    public IReadOnlyDictionary<CollectionModule, bool> ActiveModules { get; init; } =
        new Dictionary<CollectionModule, bool>();
    public double EventsPerMinute { get; init; }
    public double CpuPercentToday { get; init; }
    public long WorkingSetBytes { get; init; }
    public string? LastError { get; init; }
    public DateTimeOffset? StartedUtc { get; init; }
}
