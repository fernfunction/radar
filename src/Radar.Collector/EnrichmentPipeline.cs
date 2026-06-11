using System.Collections.Concurrent;
using Radar.Core.Analysis;
using Radar.Core.Model;
using Radar.Windows;

namespace Radar.Collector;

/// <summary>
/// Pipeline de enriquecimento: a cada criação de processo monta o dossiê em tempo
/// real: identidade (hash/MOTW/versão), contexto de segurança, atribuição de origem, masquerading,
/// fila de assinaturas com vazão limitada e score explicável recomputado a cada fato novo.
/// </summary>
public sealed class EnrichmentPipeline : IDisposable
{
    private readonly CollectorContext _ctx;
    private readonly BlockingCollection<ExecutionTracker> _identityQueue = new(boundedCapacity: 4096);
    private readonly ConcurrentQueue<ExecutionTracker> _signatureQueue = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread _identityWorker;
    private readonly System.Threading.Timer _rescoreTimer;
    private long _hashOpsWindowStart = Environment.TickCount64;
    private int _hashOpsInWindow;

    /// <summary>Notificação de achado Crítico (consumida pela bandeja/toast).</summary>
    public event Action<ProcessExecution>? CriticalFinding;

    public EnrichmentPipeline(CollectorContext ctx)
    {
        _ctx = ctx;
        _identityWorker = new Thread(IdentityWorkerLoop) { IsBackground = true, Name = "radar-enrich" };
        _identityWorker.Start();
        _rescoreTimer = new System.Threading.Timer(_ => RescoreDirty(), null,
            TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    public void OnProcessStart(int pid, string imagePath, string? commandLine, int creatorPid,
        DateTimeOffset createdUtc)
    {
        if (!_ctx.ModuleOn(CollectionModule.Processes)) return;
        if (_ctx.IsExcludedFromCollection(imagePath)) return; // privacidade ativa

        var creatorTracker = _ctx.FindTracker(creatorPid);
        var creatorImage = creatorTracker?.Execution.Binary.Path ?? ProcessInspector.GetImagePath(creatorPid);

        // Pai declarado (PEB) vs criador real (ETW): divergência indica spoofing
        var declaredParent = ProcessInspector.GetDeclaredParentPid(pid) ?? creatorPid;
        var declaredParentImage = declaredParent == creatorPid
            ? creatorImage
            : _ctx.FindTracker(declaredParent)?.Execution.Binary.Path ?? ProcessInspector.GetImagePath(declaredParent);

        // Snapshot da ancestralidade (os pais podem morrer)
        var ancestry = new List<AncestryLink>();
        var cursor = creatorTracker;
        var cursorPid = creatorPid;
        var cursorImage = creatorImage;
        for (var depth = 0; depth < 16 && cursorPid != 0; depth++)
        {
            ancestry.Add(new AncestryLink(cursorPid, cursorImage, cursor?.Execution.CreatedUtc));
            if (cursor is null) break;
            cursorPid = cursor.Execution.CreatorPid;
            cursor = _ctx.FindTracker(cursorPid);
            cursorImage = cursor?.Execution.Binary.Path ?? ProcessInspector.GetImagePath(cursorPid);
        }

        var security = ProcessInspector.Inspect(pid);

        var execution = new ProcessExecution
        {
            ExecutionId = Guid.NewGuid(),
            Pid = pid,
            CreatedUtc = createdUtc,
            CommandLine = commandLine,
            Binary = new BinaryIdentity { Path = imagePath },
            Security = security,
            DeclaredParentPid = declaredParent,
            DeclaredParentImage = declaredParentImage,
            CreatorPid = creatorPid,
            CreatorImage = creatorImage,
            ParentExecutionId = creatorTracker?.ExecutionId,
            Ancestry = ancestry,
        };

        var tracker = new ExecutionTracker(execution);
        _ctx.LiveByPid[pid] = tracker;

        // O arquivo recém-criado por um dropper acabou de virar processo? (linhagem)
        if (_ctx.DroppedFileToCreator.TryGetValue(imagePath, out var creatorExecId) &&
            _ctx.FindTrackerByExecution(creatorExecId) is { } dropperTracker)
        {
            dropperTracker.DroppedExecutableLaterExecuted = true;
            dropperTracker.DropEvidence.Add($"{imagePath} ran as PID {pid}");
            dropperTracker.Dirty = true;
        }

        if (!_identityQueue.TryAdd(tracker))
            _ctx.Log.Warning("Enrichment queue full; identity of PID {Pid} deferred", pid);

        _ctx.Store.AddTimelineEvent(new TimelineEvent
        {
            TimestampUtc = createdUtc,
            Kind = TimelineEventKind.ProcessStart,
            ExecutionId = execution.ExecutionId,
            Title = $"Process created: {execution.Binary.FileName}",
            Detail = imagePath,
        });
    }

    public void OnProcessStop(int pid, int? exitCode, DateTimeOffset exitedUtc)
    {
        if (_ctx.LiveByPid.TryRemove(pid, out var tracker))
        {
            tracker.MarkExited(exitedUtc, exitCode);
            _ctx.RecentExited[tracker.ExecutionId] = tracker;

            FlushConnections(tracker);
            Rescore(tracker);

            _ctx.Store.AddTimelineEvent(new TimelineEvent
            {
                TimestampUtc = exitedUtc,
                Kind = TimelineEventKind.ProcessEnd,
                ExecutionId = tracker.ExecutionId,
                Title = $"Process ended: {tracker.Execution.Binary.FileName}",
                Detail = $"duration {ScoreEngine.FormatDuration(tracker.Execution.Duration)}",
                Score = tracker.Execution.Score?.Total ?? 0,
            });

            // Auto-deleção: o binário some segundos após o término
            if (_ctx.ModuleOn(CollectionModule.FileSelfDelete))
                ScheduleSelfDeleteCheck(tracker);
        }
    }

    private void ScheduleSelfDeleteCheck(ExecutionTracker tracker)
    {
        Task.Delay(TimeSpan.FromSeconds(6), _cts.Token).ContinueWith(t =>
        {
            if (t.IsCanceled) return;
            try
            {
                var path = tracker.Execution.Binary.Path;
                if (path.Length > 0 && !File.Exists(path) &&
                    Core.Filtering.VisibilityFilter.IsUserWritableDirectory(path))
                {
                    tracker.SelfDeleted = true;
                    _ctx.Store.AddFileActivity(new FileActivity
                    {
                        ExecutionId = tracker.ExecutionId,
                        TimestampUtc = DateTimeOffset.UtcNow,
                        Kind = FileEventKind.SelfDelete,
                        Path = path,
                    });
                    _ctx.Store.AddTimelineEvent(new TimelineEvent
                    {
                        TimestampUtc = DateTimeOffset.UtcNow,
                        Kind = TimelineEventKind.SelfDelete,
                        ExecutionId = tracker.ExecutionId,
                        Title = $"Self-deletion: {tracker.Execution.Binary.FileName}",
                        Detail = path,
                    });
                    Rescore(tracker);
                }
            }
            catch (Exception ex)
            {
                _ctx.Log.Debug(ex, "Self-deletion check failed");
            }
        }, TaskScheduler.Default);
    }

    private void IdentityWorkerLoop()
    {
        foreach (var tracker in _identityQueue.GetConsumingEnumerable(_cts.Token.IsCancellationRequested
                     ? CancellationToken.None : _cts.Token))
        {
            try
            {
                EnrichIdentity(tracker);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                _ctx.Log.Warning(ex, "Enrichment failed for {Path}", tracker.Execution.Binary.Path);
            }
        }
    }

    private void EnrichIdentity(ExecutionTracker tracker)
    {
        ThrottleHashOps();
        var exec = tracker.Execution;
        var identity = FileMetadataReader.Read(exec.Binary.Path, DateTimeOffset.UtcNow, _ctx.Lists);

        var novelty = _ctx.BaselineEngine.Evaluate(_ctx.BaselineState, exec with { Binary = identity });
        tracker.IsFirstRunOfBinary = novelty.FirstRunOfBinary;
        tracker.PriorRunCount = identity.Sha256 is { } sha ? _ctx.Store.CountPriorRuns(sha, exec.CreatedUtc) : 0;

        // Confiança manual amarrada a hash: hash mudou, reativa
        var trustList = _ctx.Store.GetTrustList();
        var trustEntry = trustList.FirstOrDefault(t =>
            t.Path.Equals(identity.Path, StringComparison.OrdinalIgnoreCase));
        if (trustEntry is not null && identity.Sha256 is { } currentHash)
        {
            if (trustEntry.Sha256.Equals(currentHash, StringComparison.OrdinalIgnoreCase))
                tracker.UserMarkedTrusted = true;
            else
                tracker.HashChangedSinceTrusted = true;
        }

        // Hash divergente para o mesmo caminho
        var previousHash = _ctx.Store.GetLastHashForPath(identity.Path);

        // Atribuição de origem: resolvida agora, enquanto o contexto existe
        var persistence = _ctx.Store.GetPersistenceEntries();
        var parentDead = exec.CreatorPid != 0 && !_ctx.LiveByPid.ContainsKey(exec.CreatorPid) &&
                         _ctx.FindTracker(exec.CreatorPid) is null;
        var hints = _ctx.OriginResolver.BuildHints(exec.Pid, exec.CreatorImage, exec.CommandLine,
            parentDead, persistence, identity.Path);

        tracker.Mutate(e =>
        {
            var withIdentity = e with { Binary = identity with { Signature = e.Binary.Signature } };
            return withIdentity with
            {
                Origin = _ctx.Attributor.Attribute(withIdentity, hints),
                PriorRunCountSameBinary = tracker.PriorRunCount,
            };
        });
        tracker.IdentityEnriched = true;

        if (novelty.FirstRunOfBinary)
        {
            _ctx.Store.AddTimelineEvent(new TimelineEvent
            {
                TimestampUtc = exec.CreatedUtc,
                Kind = TimelineEventKind.FirstRunOfNewBinary,
                ExecutionId = exec.ExecutionId,
                Title = $"First run of a never-seen binary: {identity.FileName}",
                Detail = identity.Path,
            });
        }

        _ctx.BaselineEngine.Absorb(_ctx.BaselineState, exec with { Binary = identity });

        _signatureQueue.Enqueue(tracker);

        Rescore(tracker, previousHashForPath: previousHash);
    }

    private void ThrottleHashOps()
    {
        var max = Math.Max(10, _ctx.Settings.Rates.MaxHashOperationsPerMinute);
        while (true)
        {
            var elapsed = Environment.TickCount64 - Interlocked.Read(ref _hashOpsWindowStart);
            if (elapsed >= 60_000)
            {
                Interlocked.Exchange(ref _hashOpsWindowStart, Environment.TickCount64);
                Interlocked.Exchange(ref _hashOpsInWindow, 0);
            }
            if (Interlocked.Increment(ref _hashOpsInWindow) <= max) return;
            Thread.Sleep(500); // nunca competir com o uso interativo da máquina
        }
    }

    public void ProcessSignatureBatch()
    {
        var batchLimit = _ctx.Settings.Rates.MaxSignatureVerificationsPerBatch;
        var processed = 0;
        while (processed < batchLimit && _signatureQueue.TryDequeue(out var tracker))
        {
            processed++;
            try
            {
                var binary = tracker.Execution.Binary;
                var signature = _ctx.Signatures.Verify(binary.Path, binary.Sha256);
                tracker.Mutate(e => e with { Binary = e.Binary with { Signature = signature } });

                if (signature is { Status: SignatureStatus.SignedTrusted, Subject: { } subject })
                {
                    tracker.SignerHasReputation = _ctx.BaselineState.KnownSignerSubjects.Contains(subject) &&
                                                  _ctx.BaselineState.LearningComplete(DateTimeOffset.UtcNow);
                    _ctx.BaselineState.KnownSignerSubjects.Add(subject);
                }
                Rescore(tracker);
            }
            catch (Exception ex)
            {
                _ctx.Log.Debug(ex, "Signature verification failed");
            }
        }
        if (processed > 0)
            _ctx.Log.Debug("Signature batch processed: {Count} binaries", processed);
    }

    public void Rescore(ExecutionTracker tracker, string? previousHashForPath = null)
    {
        var exec = tracker.Execution;

        MasqueradingFindings? masq = null;
        if (tracker.IdentityEnriched)
        {
            masq = _ctx.Masquerading.Analyze(new MasqueradingInput
            {
                ImagePath = exec.Binary.Path,
                Version = exec.Binary.Version,
                Signature = exec.Binary.Signature,
                Indicators = exec.Binary.Indicators,
                PreviousHashForPath = previousHashForPath,
                CurrentHash = exec.Binary.Sha256,
                HashChangeExplainedByUpdate = false,
                ParentForged = exec.CreatorPid != 0 && exec.DeclaredParentPid != 0 &&
                               exec.CreatorPid != exec.DeclaredParentPid,
            });
        }

        var cmdline = _ctx.CommandLineAnalyzer.Analyze(exec.Binary.FileName, exec.CommandLine);
        var facts = tracker.BuildFacts(masq, cmdline);
        var score = _ctx.ScoreEngine.Compute(facts);

        tracker.Mutate(e => e with { Score = score });
        _ctx.Store.UpsertExecution(tracker.Execution);
        tracker.Dirty = false;

        if (!score.Muted && score.Band >= _ctx.Settings.Notifications.MinimumBand &&
            score.Band > tracker.LastNotifiedBand)
        {
            tracker.LastNotifiedBand = score.Band;
            if (score.Band == ScoreBand.Critical) Interlocked.Increment(ref _ctx.CriticalUnseen);
            CriticalFinding?.Invoke(tracker.Execution);
        }
    }

    private void RescoreDirty()
    {
        try
        {
            foreach (var tracker in _ctx.LiveByPid.Values.Concat(_ctx.RecentExited.Values))
            {
                if (tracker.Dirty && tracker.IdentityEnriched) Rescore(tracker);
            }
            _ctx.TrimRecent(TimeSpan.FromMinutes(10));
        }
        catch (Exception ex)
        {
            _ctx.Log.Debug(ex, "Periodic rescore failed");
        }
    }

    public void FlushConnections(ExecutionTracker tracker)
    {
        foreach (var connection in tracker.DrainUnstoredConnections())
            _ctx.Store.AddNetworkConnection(connection);
    }

    public void Dispose()
    {
        _cts.Cancel();
        _identityQueue.CompleteAdding();
        _rescoreTimer.Dispose();
    }
}
