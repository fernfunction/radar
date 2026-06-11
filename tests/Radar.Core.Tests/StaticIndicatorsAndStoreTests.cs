using Radar.Core.Abstractions;
using Radar.Core.Analysis;
using Radar.Core.Model;
using Radar.Data;

namespace Radar.Core.Tests;

public class StaticIndicatorAnalyzerTests
{
    [Theory]
    [InlineData("fatura.pdf.exe", true)]
    [InlineData("planilha.xlsx.scr", true)]
    [InlineData("foto.jpg.vbs", true)]
    [InlineData("setup.exe", false)]
    [InlineData("documento.pdf", false)]
    [InlineData("app.config.json", false)]
    public void Double_extension_detection(string fileName, bool expected) =>
        Assert.Equal(expected, StaticIndicatorAnalyzer.HasDoubleExtension(fileName));

    [Theory]
    [InlineData("qjzkx8f2nval.exe", true)]
    [InlineData("a8f3k2j9x7qz.exe", true)]
    [InlineData("notepad.exe", false)]
    [InlineData("setup-wizard.exe", false)]
    [InlineData("GoogleUpdate.exe", false)]
    public void Random_looking_name_detection(string fileName, bool expected) =>
        Assert.Equal(expected, StaticIndicatorAnalyzer.HasRandomLookingName(fileName));

    [Fact]
    public void Entropy_high_for_random_low_for_repetitive()
    {
        var random = new byte[64 * 1024];
        new Random(42).NextBytes(random);
        using var randomStream = new MemoryStream(random);
        Assert.True(StaticIndicatorAnalyzer.ShannonEntropy(randomStream) > 7.5);

        var repetitive = new byte[64 * 1024]; // tudo zero
        using var flatStream = new MemoryStream(repetitive);
        Assert.True(StaticIndicatorAnalyzer.ShannonEntropy(flatStream) < 0.1);
    }

    [Fact]
    public void Rlo_character_detected()
    {
        var indicators = StaticIndicatorAnalyzer.Analyze("C:\\Temp\\fatura‮fdp.exe");
        Assert.True(indicators.HasRloCharacter);
    }
}

/// <summary>Ida e volta no banco: o dossiê sobrevive intacto à serialização.</summary>
public class SqliteEventStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"radar-test-{Guid.NewGuid():N}.db");
    private readonly SqliteEventStore _store;

    public SqliteEventStoreTests() => _store = new SqliteEventStore(_dbPath);

    public void Dispose()
    {
        _store.Dispose();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch { }
        }
    }

    [Fact]
    public void Execution_roundtrip_preserves_dossier()
    {
        var exec = TestData.Execution(commandLine: "payload.exe --exfil",
            duration: TimeSpan.FromSeconds(4)) with
        {
            Score = new SuspicionScore
            {
                Total = 95,
                Signals =
                [
                    new Signal
                    {
                        Kind = SignalKind.CredentialDirectoryRead, Weight = 35,
                        Title = "Leitura de credenciais", Explanation = "leu cofre do Chrome",
                        Evidence = [@"C:\Users\alice\AppData\Local\Google\Chrome\User Data"],
                    },
                ],
            },
            Ancestry = [new AncestryLink(100, @"C:\Windows\explorer.exe", null)],
            Origin = new OriginAttribution
            {
                Origin = LaunchOrigin.UserExplorer,
                Description = "Disparado pelo usuário via Explorer.",
            },
        };

        _store.UpsertExecution(exec);
        var loaded = _store.GetExecution(exec.ExecutionId);

        Assert.NotNull(loaded);
        Assert.Equal(exec.Binary.Sha256, loaded.Binary.Sha256);
        Assert.Equal(exec.CommandLine, loaded.CommandLine);
        Assert.Equal(95, loaded.Score!.Total);
        Assert.Equal(SignalKind.CredentialDirectoryRead, loaded.Score.Signals[0].Kind);
        Assert.Single(loaded.Ancestry);
        Assert.Equal(LaunchOrigin.UserExplorer, loaded.Origin!.Origin);
        Assert.Equal(exec.Duration!.Value.TotalSeconds, loaded.Duration!.Value.TotalSeconds, 1);
    }

    [Fact]
    public void Query_filters_by_score_signature_and_text()
    {
        _store.UpsertExecution(TestData.Execution(sha256: "A1") with
        { Score = new SuspicionScore { Total = 90 } });
        _store.UpsertExecution(TestData.Execution(
            path: @"C:\Program Files\ok\ok.exe", signature: SignatureStatus.SignedTrusted, sha256: "B2"));

        Assert.Single(_store.QueryExecutions(new ExecutionQuery { MinScore = 50 }));
        Assert.Single(_store.QueryExecutions(new ExecutionQuery { SignatureStatus = SignatureStatus.SignedTrusted }));
        Assert.Single(_store.QueryExecutions(new ExecutionQuery { SearchText = "payload" }));
        Assert.Equal(2, _store.QueryExecutions(new ExecutionQuery()).Count);
    }

    [Fact]
    public void Network_and_dns_search_links_to_execution()
    {
        var exec = TestData.Execution();
        _store.UpsertExecution(exec);
        _store.AddDnsQuery(new DnsQuery
        {
            ExecutionId = exec.ExecutionId,
            TimestampUtc = exec.CreatedUtc,
            Domain = "exfil.evil-domain.xyz",
            ResolvedAddresses = ["203.0.113.5"],
        });
        _store.AddNetworkConnection(new NetworkConnection
        {
            ExecutionId = exec.ExecutionId,
            FirstSeenUtc = exec.CreatedUtc,
            RemoteAddress = "203.0.113.5",
            RemotePort = 443,
            BytesSent = 1_800_000,
            ResolvedFromDomain = "exfil.evil-domain.xyz",
        });

        // Busca por domínio acha a execução
        Assert.Single(_store.QueryExecutions(new ExecutionQuery { SearchText = "evil-domain" }));
        // Busca por IP também
        Assert.Single(_store.QueryExecutions(new ExecutionQuery { SearchText = "203.0.113.5" }));
        // has_network marcado
        Assert.Single(_store.QueryExecutions(new ExecutionQuery { HasNetworkActivity = true }));

        var conns = _store.GetConnections(exec.ExecutionId);
        Assert.Equal(1_800_000, Assert.Single(conns).BytesSent);
    }

    [Fact]
    public void Prior_runs_counted_and_last_hash_for_path()
    {
        var older = TestData.Execution(created: DateTimeOffset.UtcNow.AddDays(-2), sha256: "SAME");
        var newer = TestData.Execution(created: DateTimeOffset.UtcNow, sha256: "SAME");
        _store.UpsertExecution(older);
        _store.UpsertExecution(newer);

        Assert.Equal(1, _store.CountPriorRuns("SAME", newer.CreatedUtc));
        Assert.Equal("SAME", _store.GetLastHashForPath(newer.Binary.Path));
    }

    [Fact]
    public void Purge_summarizes_old_executions()
    {
        var old = TestData.Execution(created: DateTimeOffset.UtcNow.AddDays(-60), sha256: "OLD1");
        var recent = TestData.Execution(created: DateTimeOffset.UtcNow, sha256: "NEW1");
        _store.UpsertExecution(old);
        _store.UpsertExecution(recent);

        var result = _store.PurgeAndSummarize(DateTimeOffset.UtcNow.AddDays(-30), long.MaxValue);

        Assert.Null(_store.GetExecution(old.ExecutionId));
        Assert.NotNull(_store.GetExecution(recent.ExecutionId));
        // O resumo preserva a prevalência histórica
        Assert.Equal(1, _store.CountPriorRuns("OLD1", DateTimeOffset.UtcNow));
        Assert.True(result.EventsPurged > 0);
    }

    [Fact]
    public void Trust_list_and_verdict_roundtrip()
    {
        var exec = TestData.Execution();
        _store.UpsertExecution(exec);
        _store.AddTrustListEntry(new Core.Filtering.TrustListEntry
        {
            Sha256 = exec.Binary.Sha256!,
            Path = exec.Binary.Path,
            SignerSubject = null,
            AddedUtc = DateTimeOffset.UtcNow,
        });
        Assert.Single(_store.GetTrustList());

        _store.SetVerdict(exec.ExecutionId, UserVerdict.Suspicious, "investigar amanhã");
        var loaded = _store.GetExecution(exec.ExecutionId);
        Assert.Equal(UserVerdict.Suspicious, loaded!.Verdict);
        Assert.Equal("investigar amanhã", loaded.UserNotes);

        _store.RemoveTrustListEntry(exec.Binary.Sha256!);
        Assert.Empty(_store.GetTrustList());
    }

    [Fact]
    public void Persistence_entries_roundtrip_with_removal()
    {
        var entry = new PersistenceEntry
        {
            Id = PersistenceDiffer.StableId(PersistenceKind.ScheduledTask, "TaskScheduler", @"\Evil\Task"),
            Kind = PersistenceKind.ScheduledTask,
            Location = @"\Evil\Task",
            Name = "Task",
            Target = @"C:\Temp\payload.exe",
            TargetBinaryPath = @"C:\Temp\payload.exe",
            FirstSeenUtc = DateTimeOffset.UtcNow,
            LastSeenUtc = DateTimeOffset.UtcNow,
        };
        _store.UpsertPersistenceEntry(entry);
        Assert.Single(_store.GetPersistenceEntries());
        Assert.Single(_store.GetPersistenceForTarget(@"C:\Temp\payload.exe"));

        _store.MarkPersistenceRemoved(entry.Id, DateTimeOffset.UtcNow);
        Assert.Empty(_store.GetPersistenceEntries(includeRemoved: false));
        Assert.Single(_store.GetPersistenceEntries(includeRemoved: true));
    }

    [Fact]
    public void Baseline_roundtrip()
    {
        var state = _store.LoadBaseline();
        state.KnownBinaryHashes.Add("XYZ");
        state.Prevalence["XYZ"] = new PrevalenceInfo(3, DateTimeOffset.UtcNow.AddDays(-5));
        _store.SaveBaseline(state);

        var loaded = _store.LoadBaseline();
        Assert.Contains("XYZ", loaded.KnownBinaryHashes);
        Assert.Equal(3, loaded.Prevalence["XYZ"].RunCount);
    }

    [Fact]
    public void Timeline_filters_by_score_but_keeps_system_markers()
    {
        var now = DateTimeOffset.UtcNow;
        _store.AddTimelineEvent(new TimelineEvent
        { TimestampUtc = now, Kind = TimelineEventKind.ProcessStart, Title = "baixo", Score = 5 });
        _store.AddTimelineEvent(new TimelineEvent
        { TimestampUtc = now, Kind = TimelineEventKind.ProcessStart, Title = "alto", Score = 90 });
        _store.AddSystemMarker(new SystemMarker { TimestampUtc = now, Kind = SystemMarkerKind.Logon });

        var filtered = _store.GetTimeline(now.AddMinutes(-1), now.AddMinutes(1), minScore: 50);
        Assert.Equal(2, filtered.Count); // "alto" + marcador de sistema
        Assert.Contains(filtered, e => e.Kind == TimelineEventKind.SystemMarker);
    }
}

public class InvestigationReportTests
{
    [Fact]
    public void Html_report_contains_score_and_indicators()
    {
        var exec = TestData.Execution(commandLine: "payload --send") with
        {
            Score = new SuspicionScore
            {
                Total = 80,
                Signals =
                [
                    new Signal
                    {
                        Kind = SignalKind.ShortLivedWithUpload, Weight = 25,
                        Title = "Vida curta com upload", Explanation = "enviou 1,8 MB em 4s",
                    },
                ],
            },
        };
        var report = new Core.Reporting.InvestigationReport
        {
            Execution = exec,
            GeneratedUtc = DateTimeOffset.UtcNow,
            DnsQueries =
            [
                new DnsQuery
                {
                    ExecutionId = exec.ExecutionId, TimestampUtc = exec.CreatedUtc,
                    Domain = "evil.xyz",
                },
            ],
        };

        var html = report.ToHtml();
        Assert.Contains("payload.exe", html);
        Assert.Contains("80", html);
        Assert.Contains("Vida curta com upload", html);
        Assert.Contains("not an antivirus", html);

        var indicators = report.FormatIndicators();
        Assert.Contains(exec.Binary.Sha256!, indicators);
        Assert.Contains("evil.xyz", indicators);

        // JSON é desserializável
        Assert.Contains("\"Total\": 80", report.ToJson());
    }

    [Fact]
    public void Removal_plan_lists_persistence_files_and_siblings()
    {
        var exec = TestData.Execution(duration: TimeSpan.FromSeconds(3));
        var persistence = new PersistenceEntry
        {
            Id = "p1", Kind = PersistenceKind.RunKey, Location = @"HKCU\Run",
            Name = "Updater", Target = exec.Binary.Path,
            FirstSeenUtc = exec.CreatedUtc, LastSeenUtc = exec.CreatedUtc,
        };
        var dropped = new FileActivity
        {
            ExecutionId = exec.ExecutionId, TimestampUtc = exec.CreatedUtc,
            Kind = FileEventKind.ExecutableDrop, Path = @"C:\Temp\stage2.exe",
        };
        var sibling = TestData.Execution(path: @"C:\Temp\stage2.exe", sha256: "S2");

        var items = Core.Reporting.RemovalPlanBuilder.Build(exec, [persistence], [dropped], [sibling]);

        Assert.Contains(items, i => i.Kind == Core.Reporting.RemovalItemKind.RemovePersistence &&
                                    i.Title.Contains("Updater"));
        Assert.Contains(items, i => i.Kind == Core.Reporting.RemovalItemKind.DeleteFile &&
                                    i.Title.Contains("stage2.exe"));
        Assert.Contains(items, i => i.Kind == Core.Reporting.RemovalItemKind.ReviewSibling);
        // Processo já morto: não pede para encerrar
        Assert.DoesNotContain(items, i => i.Kind == Core.Reporting.RemovalItemKind.KillProcess);
    }
}
