using System.Text.Json;
using Radar.Core.Configuration;
using Radar.Core.Model;
using Radar.Data;

namespace Radar.Collector;

/// <summary>
/// Rotinas periódicas com intervalos configuráveis e limites de proteção:
/// varredura de persistência, fila de assinaturas, expurgo/sumarização, baseline, snapshot,
/// checkpoint do banco, amostragem de recursos, beaconing e recarga de configurações a quente.
/// </summary>
public sealed class PeriodicRoutines : IDisposable
{
    private readonly CollectorContext _ctx;
    private readonly EnrichmentPipeline _pipeline;
    private readonly EtwCollector _etw;
    private readonly List<System.Threading.Timer> _timers = [];
    private readonly FileSystemWatcher? _settingsWatcher;
    private DateTimeOffset _lastPurge = DateTimeOffset.MinValue;
    private DateTimeOffset _lastBaselineSave = DateTimeOffset.MinValue;
    private DateTimeOffset _lastSnapshot = DateTimeOffset.MinValue;
    private readonly Dictionary<int, (TimeSpan CpuTime, DateTimeOffset At)> _cpuBaseline = [];

    public PeriodicRoutines(CollectorContext ctx, EnrichmentPipeline pipeline, EtwCollector etw)
    {
        _ctx = ctx;
        _pipeline = pipeline;
        _etw = etw;

        var rates = ctx.Settings.Rates;

        Schedule(TimeSpan.FromSeconds(rates.SignatureQueueBatchSeconds), () =>
        {
            _pipeline.ProcessSignatureBatch();
            _etw.RelaxBackpressure();
        });
        Schedule(TimeSpan.FromMinutes(rates.PersistenceScanMinutes), ScanPersistence, runImmediately: true);
        Schedule(TimeSpan.FromSeconds(rates.DbCheckpointSeconds), () => _ctx.Store.Checkpoint());
        Schedule(TimeSpan.FromMinutes(15), HourlyMaintenance);
        Schedule(TimeSpan.FromSeconds(15), SampleResources);
        Schedule(TimeSpan.FromSeconds(60), FlushLiveConnections);
        Schedule(TimeSpan.FromMinutes(5), AnalyzeBeaconing);

        // Mudanças de coleta aplicam sem reiniciar e ficam no log operacional
        try
        {
            var dir = Path.GetDirectoryName(ctx.Settings.SettingsPath)!;
            Directory.CreateDirectory(dir);
            _settingsWatcher = new FileSystemWatcher(dir, "settings.json")
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName,
                EnableRaisingEvents = true,
            };
            _settingsWatcher.Changed += (_, _) => ReloadSettings();
            _settingsWatcher.Created += (_, _) => ReloadSettings();
        }
        catch (Exception ex)
        {
            ctx.Log.Warning(ex, "Settings watcher unavailable - changes will require a restart");
        }
    }

    private void Schedule(TimeSpan interval, Action action, bool runImmediately = false)
    {
        _timers.Add(new System.Threading.Timer(_ =>
        {
            if (_ctx.StopRequested) return;
            try { action(); }
            catch (Exception ex) { _ctx.Log.Warning(ex, "Periodic routine failed"); }
        }, null, runImmediately ? TimeSpan.FromSeconds(10) : interval, interval));
    }

    private void ReloadSettings()
    {
        try
        {
            Thread.Sleep(300); // espera o arquivo fechar
            var reloaded = RadarSettings.LoadOrDefault(_ctx.Settings.SettingsPath);
            reloaded.DataRoot = _ctx.Settings.DataRoot;
            var before = _ctx.Settings;
            _ctx.Settings = reloaded;
            _ctx.ScoreEngine = new Core.Analysis.ScoreEngine(reloaded.ScoreWeights);

            foreach (var module in Enum.GetValues<CollectionModule>())
            {
                if (before.IsModuleEnabled(module) != reloaded.IsModuleEnabled(module))
                    _ctx.Log.Information("Collection module {Module}: {State}", module,
                        reloaded.IsModuleEnabled(module) ? "ON" : "OFF");
            }
            _ctx.Log.Information("Settings hot-reloaded");
        }
        catch (Exception ex)
        {
            _ctx.Log.Warning(ex, "Failed to reload settings");
        }
    }

    private void ScanPersistence()
    {
        if (!_ctx.ModuleOn(CollectionModule.PersistenceScan)) return;
        var now = DateTimeOffset.UtcNow;
        var current = _ctx.PersistenceScanner.ScanAll(now);
        var previous = _ctx.Store.GetPersistenceEntries(includeRemoved: false);
        var diff = PersistenceDiffer.Diff(previous, current, now);

        foreach (var added in diff.Added)
        {
            // Avaliação com os mesmos critérios de binário
            var enriched = added;
            if (added.TargetBinaryPath is { } binPath && File.Exists(binPath))
                enriched = added with { Signature = _ctx.Signatures.Verify(binPath) };

            // Correlação com o instalador: execução recente cujo binário/drop corresponde ao alvo
            var installer = FindInstallerExecution(enriched);
            if (installer is not null)
            {
                enriched = enriched with { InstallerExecutionId = installer.ExecutionId };
                installer.InstalledPersistence = true;
                installer.PersistenceEvidence.Add($"{enriched.Kind}: {enriched.Name}");
                installer.Dirty = true;
            }

            _ctx.Store.UpsertPersistenceEntry(enriched);
            _ctx.BaselineState.KnownPersistenceIds.Add(enriched.Id);
            _ctx.Store.AddTimelineEvent(new TimelineEvent
            {
                TimestampUtc = now,
                Kind = TimelineEventKind.PersistenceInstalled,
                ExecutionId = enriched.InstallerExecutionId,
                Title = $"Persistence added: {enriched.Name} ({enriched.Kind})",
                Detail = enriched.Target,
            });
        }

        foreach (var (before, after) in diff.Changed)
        {
            _ctx.Store.UpsertPersistenceEntry(after with { FirstSeenUtc = before.FirstSeenUtc });
            _ctx.Store.AddTimelineEvent(new TimelineEvent
            {
                TimestampUtc = now,
                Kind = TimelineEventKind.PersistenceInstalled,
                Title = $"Persistence changed: {after.Name} ({after.Kind})",
                Detail = $"{before.Target} → {after.Target}",
            });
        }

        foreach (var removed in diff.Removed)
            _ctx.Store.MarkPersistenceRemoved(removed.Id, now);

        foreach (var entry in current.Where(c => previous.Any(p => p.Id == c.Id)))
            _ctx.Store.UpsertPersistenceEntry(entry with
            {
                FirstSeenUtc = previous.First(p => p.Id == entry.Id).FirstSeenUtc,
                InstallerExecutionId = previous.First(p => p.Id == entry.Id).InstallerExecutionId,
            });

        if (diff.HasChanges)
            _ctx.Log.Information("Persistence scan: +{Added} ~{Changed} -{Removed}",
                diff.Added.Count, diff.Changed.Count, diff.Removed.Count);
    }

    private ExecutionTracker? FindInstallerExecution(PersistenceEntry entry)
    {
        var target = entry.TargetBinaryPath;
        foreach (var tracker in _ctx.LiveByPid.Values.Concat(_ctx.RecentExited.Values))
        {
            var exec = tracker.Execution;
            if (target is not null &&
                (exec.Binary.Path.Equals(target, StringComparison.OrdinalIgnoreCase) ||
                 tracker.DroppedPaths.Contains(target)))
                return tracker;
            if (entry.Target.Contains(exec.Binary.Path, StringComparison.OrdinalIgnoreCase))
                return tracker;
        }
        return null;
    }

    private void HourlyMaintenance()
    {
        var now = DateTimeOffset.UtcNow;
        var rates = _ctx.Settings.Rates;

        if (now - _lastPurge >= TimeSpan.FromHours(rates.RetentionPurgeHours))
        {
            _lastPurge = now;
            var cutoff = now - TimeSpan.FromDays(_ctx.Settings.Retention.RawEventDays);
            var result = _ctx.Store.PurgeAndSummarize(cutoff, _ctx.Settings.Retention.MaxDatabaseMegabytes * 1024L * 1024L);
            _ctx.Log.Information("Retention purge: {Summarized} summaries, {Purged} rows removed, database at {Mb:0.#} MB",
                result.ExecutionsSummarized, result.EventsPurged, result.DatabaseBytes / (1024.0 * 1024));
        }

        if (now - _lastBaselineSave >= TimeSpan.FromHours(Math.Min(rates.BaselineRecomputeHours, 4)))
        {
            _lastBaselineSave = now;
            if (_ctx.ModuleOn(CollectionModule.Baseline))
            {
                _ctx.Store.SaveBaseline(_ctx.BaselineState);
                _ctx.Log.Debug("Baseline persisted ({Hashes} hashes, {Domains} domains)",
                    _ctx.BaselineState.KnownBinaryHashes.Count, _ctx.BaselineState.KnownDomains.Count);
            }
        }

        if (now - _lastSnapshot >= TimeSpan.FromDays(rates.AutoSnapshotDays))
        {
            _lastSnapshot = now;
            var snapshot = new MachineSnapshot
            {
                TakenUtc = now,
                Label = "automatic",
                KnownBinaries = _ctx.BaselineState.Prevalence.Keys
                    .ToDictionary(h => h, _ => string.Empty, StringComparer.OrdinalIgnoreCase),
                PersistenceIds = [.. _ctx.BaselineState.KnownPersistenceIds],
                NetworkDestinations = [.. _ctx.BaselineState.KnownDomains],
            };
            _ctx.Store.SaveSnapshot(snapshot);
            _ctx.Log.Information("Automatic snapshot saved");
        }
    }

    private void SampleResources()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (pid, tracker) in _ctx.LiveByPid)
        {
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                var cpuTime = proc.TotalProcessorTime;
                double cpuPercent = 0;
                if (_cpuBaseline.TryGetValue(pid, out var baseline))
                {
                    var wall = (now - baseline.At).TotalMilliseconds;
                    if (wall > 0)
                        cpuPercent = (cpuTime - baseline.CpuTime).TotalMilliseconds / wall * 100.0 /
                                     Environment.ProcessorCount;
                }
                _cpuBaseline[pid] = (cpuTime, now);

                _ctx.Store.AddResourceSample(new ResourceSample
                {
                    ExecutionId = tracker.ExecutionId,
                    TimestampUtc = now,
                    CpuPercent = Math.Round(Math.Max(0, cpuPercent), 1),
                    WorkingSetBytes = proc.WorkingSet64,
                    IoBytesPerSecond = 0,
                });
            }
            catch
            {
                _cpuBaseline.Remove(pid);
            }
        }
        foreach (var dead in _cpuBaseline.Keys.Where(p => !_ctx.LiveByPid.ContainsKey(p)).ToList())
            _cpuBaseline.Remove(dead);
    }

    private void FlushLiveConnections()
    {
        foreach (var tracker in _ctx.LiveByPid.Values)
            _pipeline.FlushConnections(tracker);
    }

    private void AnalyzeBeaconing()
    {
        foreach (var tracker in _ctx.LiveByPid.Values)
        {
            if (tracker.BeaconingDetected) continue;
            var connections = _ctx.Store.GetConnections(tracker.ExecutionId);
            if (connections.Count < 5) continue;
            var findings = _ctx.Beaconing.Analyze(connections);
            if (findings.Count > 0)
            {
                tracker.BeaconingDetected = true;
                tracker.BeaconingEvidence = findings[0].Description;
                tracker.NetworkEvidence.Add(findings[0].Destination);
                tracker.Dirty = true;
            }
        }
    }

    public void Dispose()
    {
        foreach (var timer in _timers) timer.Dispose();
        _settingsWatcher?.Dispose();
    }
}

/// <summary>
/// Saúde da coleta para a UI e comandos da UI para o coletor (pausar/retomar/encerrar)
/// via arquivos na raiz de dados: IPC simples entre os dois processos.
/// </summary>
public sealed class HealthChannel : IDisposable
{
    private readonly CollectorContext _ctx;
    private readonly System.Threading.Timer _timer;
    private readonly string _healthPath;
    private readonly string _commandPath;

    public event Action? StopCommanded;

    public HealthChannel(CollectorContext ctx)
    {
        _ctx = ctx;
        _healthPath = Path.Combine(ctx.Settings.DataRoot, "health.json");
        _commandPath = Path.Combine(ctx.Settings.DataRoot, "collector.command");
        _timer = new System.Threading.Timer(_ => Tick(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }

    private void Tick()
    {
        try
        {
            if (File.Exists(_commandPath))
            {
                var command = File.ReadAllText(_commandPath).Trim().ToLowerInvariant();
                File.Delete(_commandPath);
                switch (command)
                {
                    case "pause":
                        _ctx.Paused = true;
                        _ctx.Store.AddSystemMarker(new SystemMarker
                        { TimestampUtc = DateTimeOffset.UtcNow, Kind = SystemMarkerKind.CollectorPaused });
                        _ctx.Log.Information("Collection paused by UI command");
                        break;
                    case "resume":
                        _ctx.Paused = false;
                        _ctx.Log.Information("Collection resumed by UI command");
                        break;
                    case "stop":
                        _ctx.Log.Information("Shutdown requested by the UI");
                        StopCommanded?.Invoke();
                        break;
                    case "ack-critical":
                        Interlocked.Exchange(ref _ctx.CriticalUnseen, 0);
                        break;
                }
            }

            var health = _ctx.BuildHealth();
            var stats = _ctx.Store.GetStats();
            var payload = JsonSerializer.Serialize(new
            {
                health.Running,
                health.Paused,
                health.Elevated,
                Modules = health.ActiveModules.ToDictionary(kv => kv.Key.ToString(), kv => kv.Value),
                health.EventsPerMinute,
                health.WorkingSetBytes,
                health.LastError,
                health.StartedUtc,
                DatabaseBytes = stats.DatabaseBytes,
                ExecutionCount = stats.ExecutionCount,
                CriticalUnseen = _ctx.CriticalUnseen,
                Pid = Environment.ProcessId,
                UpdatedUtc = DateTimeOffset.UtcNow,
            });
            File.WriteAllText(_healthPath, payload);
        }
        catch
        {
            // saúde é melhor esforço
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
        try
        {
            if (File.Exists(_healthPath))
            {
                var stopped = JsonSerializer.Serialize(new { Running = false, UpdatedUtc = DateTimeOffset.UtcNow });
                File.WriteAllText(_healthPath, stopped);
            }
        }
        catch { }
    }
}
