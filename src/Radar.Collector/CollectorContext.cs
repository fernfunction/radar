using System.Collections.Concurrent;
using Radar.Core.Abstractions;
using Radar.Core.Analysis;
using Radar.Core.Catalog;
using Radar.Core.Configuration;
using Radar.Core.Filtering;
using Radar.Core.Model;
using Radar.Data;
using Radar.Windows;
using Serilog;

namespace Radar.Collector;

/// <summary>
/// Composição e estado compartilhado do coletor: configurações (recarregáveis a quente),
/// banco, analisadores, trackers vivos/recentes e contadores de saúde.
/// </summary>
public sealed class CollectorContext : IDisposable
{
    public CollectorContext(RadarSettings settings, ILogger log)
    {
        Settings = settings;
        Log = log;
        Store = new SqliteEventStore(settings.DatabasePath);
        Lists = CuratedLists.LoadOrDefault(settings.CuratedListsPath);
        CommandLineAnalyzer = new CommandLineAnalyzer(Lists);
        Masquerading = new MasqueradingAnalyzer(Lists);
        Attributor = new OriginAttributor(Lists);
        ShortLived = new ShortLivedAnalyzer(Lists);
        Filter = new VisibilityFilter(Lists, CommandLineAnalyzer);
        Beaconing = new BeaconingDetector();
        BaselineEngine = new BaselineEngine();
        BaselineState = Store.LoadBaseline();
        ScoreEngine = new ScoreEngine(settings.ScoreWeights);
        Signatures = new SignatureVerifier();
        PersistenceScanner = new PersistenceScanner();
        OriginResolver = new OriginResolver();
        Elevated = ProcessInspector.IsCurrentProcessElevated();
        StartedUtc = DateTimeOffset.UtcNow;

        // Componentes da própria aplicação ficam fora do radar
        var selfDir = AppContext.BaseDirectory;
        foreach (var exe in new[] { "Radar.Collector.exe", "Radar.App.exe" })
            Filter.OwnComponentPaths.Add(Path.Combine(selfDir, exe));
    }

    public volatile RadarSettings Settings;
    public ILogger Log { get; }
    public SqliteEventStore Store { get; }
    public CuratedLists Lists { get; }
    public CommandLineAnalyzer CommandLineAnalyzer { get; }
    public MasqueradingAnalyzer Masquerading { get; }
    public OriginAttributor Attributor { get; }
    public ShortLivedAnalyzer ShortLived { get; }
    public VisibilityFilter Filter { get; }
    public BeaconingDetector Beaconing { get; }
    public BaselineEngine BaselineEngine { get; }
    public BaselineState BaselineState { get; internal set; }
    public ScoreEngine ScoreEngine { get; internal set; }
    public SignatureVerifier Signatures { get; }
    public PersistenceScanner PersistenceScanner { get; }
    public OriginResolver OriginResolver { get; }

    public bool Elevated { get; }
    public DateTimeOffset StartedUtc { get; }
    public volatile bool Paused;
    public volatile bool StopRequested;
    public string? LastError;
    public int CriticalUnseen;

    /// <summary>Backpressure: degrada file e image load; rede nunca.</summary>
    public volatile bool FileIoDegraded;
    public volatile bool ImageLoadDegraded;

    public ConcurrentDictionary<int, ExecutionTracker> LiveByPid { get; } = new();
    public ConcurrentDictionary<Guid, ExecutionTracker> RecentExited { get; } = new();

    /// <summary>domínio para IPs resolvidos recentemente (associação DNS para conexão).</summary>
    public ConcurrentDictionary<string, string> IpToDomain { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>arquivo dropado (caminho/hash) para execução criadora (linhagem de arquivos).</summary>
    public ConcurrentDictionary<string, Guid> DroppedFileToCreator { get; } = new(StringComparer.OrdinalIgnoreCase);

    private long _eventCount;
    private long _eventCountWindowStart = Environment.TickCount64;
    private double _eventsPerMinute;

    public void CountEvent()
    {
        var count = Interlocked.Increment(ref _eventCount);
        var elapsed = Environment.TickCount64 - Interlocked.Read(ref _eventCountWindowStart);
        if (elapsed >= 30_000)
        {
            Interlocked.Exchange(ref _eventCountWindowStart, Environment.TickCount64);
            Interlocked.Exchange(ref _eventCount, 0);
            _eventsPerMinute = count * 60_000.0 / elapsed;
        }
    }

    public double EventsPerMinute => _eventsPerMinute;
    public double CurrentEventsPerSecond =>
        Interlocked.Read(ref _eventCount) * 1000.0 / Math.Max(1, Environment.TickCount64 - Interlocked.Read(ref _eventCountWindowStart));

    public bool ModuleOn(CollectionModule module) => !Paused && Settings.IsModuleEnabled(module);

    /// <summary>Exclusões de coleta: o que for excluído NÃO é sequer gravado.</summary>
    public bool IsExcludedFromCollection(string? imagePath, string? signerSubject = null)
    {
        var exclusions = Settings.Exclusions;
        if (exclusions.Count == 0) return false;
        foreach (var exclusion in exclusions)
        {
            if (exclusion.Matches(imagePath, signerSubject)) return true;
        }
        return false;
    }

    public ExecutionTracker? FindTracker(int pid)
    {
        return LiveByPid.GetValueOrDefault(pid);
    }

    public ExecutionTracker? FindTrackerByExecution(Guid executionId)
    {
        if (RecentExited.TryGetValue(executionId, out var t)) return t;
        foreach (var tracker in LiveByPid.Values)
            if (tracker.ExecutionId == executionId) return tracker;
        return null;
    }

    /// <summary>Remove trackers de processos mortos após janela de eventos atrasados.</summary>
    public void TrimRecent(TimeSpan keepFor)
    {
        var cutoff = DateTimeOffset.UtcNow - keepFor;
        foreach (var (id, tracker) in RecentExited)
        {
            if (tracker.ExitObservedUtc is { } exited && exited < cutoff)
                RecentExited.TryRemove(id, out _);
        }
    }

    public CollectorHealth BuildHealth() => new()
    {
        Running = !StopRequested,
        Paused = Paused,
        Elevated = Elevated,
        ActiveModules = Enum.GetValues<CollectionModule>()
            .ToDictionary(m => m, m => Settings.IsModuleEnabled(m) &&
                                        m switch
                                        {
                                            CollectionModule.FileSensitiveReads or CollectionModule.FileDrops
                                                or CollectionModule.FileSelfDelete => !FileIoDegraded,
                                            CollectionModule.ImageLoad => !ImageLoadDegraded,
                                            _ => true,
                                        }),
        EventsPerMinute = EventsPerMinute,
        WorkingSetBytes = Environment.WorkingSet,
        LastError = LastError,
        StartedUtc = StartedUtc,
    };

    public void Dispose() => Store.Dispose();
}
