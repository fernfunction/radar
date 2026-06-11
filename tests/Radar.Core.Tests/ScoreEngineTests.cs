using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Core.Tests;

public class ScoreEngineTests
{
    private static readonly ScoreEngine Engine = new();

    [Theory]
    [InlineData(0, ScoreBand.Informational)]
    [InlineData(24, ScoreBand.Informational)]
    [InlineData(25, ScoreBand.Attention)]
    [InlineData(49, ScoreBand.Attention)]
    [InlineData(50, ScoreBand.Suspicious)]
    [InlineData(79, ScoreBand.Suspicious)]
    [InlineData(80, ScoreBand.Critical)]
    [InlineData(150, ScoreBand.Critical)]
    public void Bands_follow_plan_thresholds(int total, ScoreBand expected) =>
        Assert.Equal(expected, SuspicionScore.BandFor(total));

    [Fact]
    public void Infostealer_profile_scores_critical_with_decomposition()
    {
        // Cenário: não assinado, %TEMP%, vida < 10s, upload externo
        var exec = TestData.Execution(duration: TimeSpan.FromSeconds(4));
        var facts = new ScoringFacts
        {
            Execution = exec,
            RunsFromUserWritableDirectory = true,
            ShortLived = true,
            UploadBytes = 1_800_000,
            ReadCredentialDirectories = true,
            CredentialReadEvidence = ["Perfil/cofre de credenciais do Chrome"],
            IsFirstRunOfBinary = true,
        };

        var score = Engine.Compute(facts);

        // +25 (unsigned writable) +25 (short+upload) +35 (credenciais) +10 (novidade) = 95
        Assert.Equal(95, score.Total);
        Assert.Equal(ScoreBand.Critical, score.Band);
        Assert.Contains(score.Signals, s => s.Kind == SignalKind.UnsignedFromWritableDir);
        Assert.Contains(score.Signals, s => s.Kind == SignalKind.ShortLivedWithUpload);
        Assert.Contains(score.Signals, s => s.Kind == SignalKind.CredentialDirectoryRead);
        Assert.Contains(score.Signals, s => s.Kind == SignalKind.NeverSeenBinary);
        // Explicabilidade total: cada sinal tem explicação
        Assert.All(score.Signals, s => Assert.False(string.IsNullOrWhiteSpace(s.Explanation)));
    }

    [Fact]
    public void Invalid_signature_is_max_highlight()
    {
        var exec = TestData.Execution(signature: SignatureStatus.SignedInvalid);
        var score = Engine.Compute(new ScoringFacts { Execution = exec });
        Assert.Contains(score.Signals, s => s.Kind == SignalKind.InvalidOrRevokedSignature && s.Weight == 40);
    }

    [Fact]
    public void Reducers_subtract_but_never_go_negative()
    {
        var exec = TestData.Execution(signature: SignatureStatus.SignedTrusted, signerSubject: "Acme Corp");
        var score = Engine.Compute(new ScoringFacts
        {
            Execution = exec,
            SignerHasEstablishedLocalReputation = true,
            LocalPrevalenceRunCount = 500,
        });
        Assert.Equal(0, score.Total);
        Assert.NotEmpty(score.Reducers);
    }

    [Fact]
    public void Trusted_mark_mutes_score_but_hash_change_reactivates()
    {
        var exec = TestData.Execution();
        var muted = Engine.Compute(new ScoringFacts
        {
            Execution = exec,
            RunsFromUserWritableDirectory = true,
            UserMarkedTrusted = true,
        });
        Assert.True(muted.Muted);

        // Anti-fadiga: reativado automaticamente se o hash mudar
        var reactivated = Engine.Compute(new ScoringFacts
        {
            Execution = exec,
            RunsFromUserWritableDirectory = true,
            UserMarkedTrusted = true,
            HashChangedSinceTrusted = true,
        });
        Assert.False(reactivated.Muted);
    }

    [Fact]
    public void Unlikely_parent_office_spawning_shell_detected()
    {
        var exec = TestData.Execution(
            path: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            creatorImage: @"C:\Program Files\Microsoft Office\WINWORD.EXE");
        Assert.True(ScoreEngine.IsUnlikelyParent(exec));

        var normal = TestData.Execution(
            path: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            creatorImage: @"C:\Windows\explorer.exe");
        Assert.False(ScoreEngine.IsUnlikelyParent(normal));
    }

    [Fact]
    public void Motw_counts_only_on_first_run()
    {
        var motw = new MarkOfTheWeb { ZoneId = 3, HostUrl = "https://evil.example/x.exe" };
        var exec = TestData.Execution(motw: motw, signature: SignatureStatus.SignedTrusted);

        var first = Engine.Compute(new ScoringFacts { Execution = exec, IsFirstRunOfBinary = true });
        Assert.Contains(first.Signals, s => s.Kind == SignalKind.MotwPresentFirstRun);

        var later = Engine.Compute(new ScoringFacts { Execution = exec, IsFirstRunOfBinary = false });
        Assert.DoesNotContain(later.Signals, s => s.Kind == SignalKind.MotwPresentFirstRun);
    }

    [Fact]
    public void Custom_weights_are_respected()
    {
        var engine = new ScoreEngine(new ScoreWeights { SelfDeletion = 70 });
        var score = engine.Compute(new ScoringFacts { Execution = TestData.Execution(), SelfDeleted = true });
        Assert.Equal(70, score.Total);
    }
}
