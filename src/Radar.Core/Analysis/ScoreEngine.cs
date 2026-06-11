using Radar.Core.Model;

namespace Radar.Core.Analysis;

/// <summary>Sinais que compõem o score. Cada um é rastreável à evidência que o originou.</summary>
public enum SignalKind
{
    InvalidOrRevokedSignature,
    Masquerading,
    CredentialDirectoryRead,
    UnsignedFromWritableDir,
    ShortLivedWithUpload,
    DropAndExecute,
    DirectIpOrDeadDrop,
    ObfuscatedCommandLineOrLolbin,
    MotwPresentFirstRun,
    UnlikelyParent,
    PersistenceOnFirstRun,
    NeverSeenBinary,
    SelfDeletion,
    PeriodicBeaconing,
    HiddenWindowWithNetwork,
    UnsignedModuleInTrustedProcess,
    ReputableSignerEstablished,
    HighLocalPrevalence,
    UserMarkedTrusted,
}

/// <summary>Um ponto do score, sempre com o porquê. Explicabilidade total.</summary>
public sealed record Signal
{
    public required SignalKind Kind { get; init; }
    public required int Weight { get; init; }
    public required string Title { get; init; }
    public required string Explanation { get; init; }
    /// <summary>Referências de evidência (ids de eventos/caminhos) que originaram o sinal.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

/// <summary>Score decomposto sinal a sinal. Cada ponto tem justificativa.</summary>
public sealed record SuspicionScore
{
    public required int Total { get; init; }
    public IReadOnlyList<Signal> Signals { get; init; } = [];
    public IReadOnlyList<Signal> Reducers { get; init; } = [];
    public ScoreBand Band => BandFor(Total);
    /// <summary>Score silenciado por marcação manual de confiança (reativa se o hash mudar).</summary>
    public bool Muted { get; init; }

    public static ScoreBand BandFor(int total) => total switch
    {
        >= 80 => ScoreBand.Critical,
        >= 50 => ScoreBand.Suspicious,
        >= 25 => ScoreBand.Attention,
        _ => ScoreBand.Informational,
    };

    public static SuspicionScore Empty { get; } = new() { Total = 0 };
}

/// <summary>Pesos configuráveis (calibráveis).</summary>
public sealed class ScoreWeights
{
    public int InvalidOrRevokedSignature { get; set; } = 40;
    public int Masquerading { get; set; } = 35;
    public int CredentialDirectoryRead { get; set; } = 35;
    public int UnsignedFromWritableDir { get; set; } = 25;
    public int ShortLivedWithUpload { get; set; } = 25;
    public int DropAndExecute { get; set; } = 20;
    public int DirectIpOrDeadDrop { get; set; } = 15;
    public int ObfuscatedCommandLineOrLolbin { get; set; } = 15;
    public int MotwPresentFirstRun { get; set; } = 10;
    public int UnlikelyParent { get; set; } = 15;
    public int PersistenceOnFirstRun { get; set; } = 15;
    public int NeverSeenBinary { get; set; } = 10;
    public int SelfDeletion { get; set; } = 20;
    public int PeriodicBeaconing { get; set; } = 15;
    public int HiddenWindowWithNetwork { get; set; } = 10;
    public int UnsignedModuleInTrustedProcess { get; set; } = 25;
    public int ReducerReputableSigner { get; set; } = -15;
    public int ReducerHighPrevalence { get; set; } = -10;
}

/// <summary>
/// Fatos observados sobre uma execução, derivados pelos analisadores. Entrada do motor de score.
/// Cada fato carrega a evidência que o suporta.
/// </summary>
public sealed class ScoringFacts
{
    public required ProcessExecution Execution { get; init; }

    public MasqueradingFindings? Masquerading { get; init; }
    public CommandLineFindings? CommandLine { get; init; }

    public bool ReadCredentialDirectories { get; init; }
    public IReadOnlyList<string> CredentialReadEvidence { get; init; } = [];

    public bool RunsFromUserWritableDirectory { get; init; }
    public bool ShortLived { get; init; }
    public long UploadBytes { get; init; }
    public long DownloadBytes { get; init; }

    public bool DroppedExecutableLaterExecuted { get; init; }
    public IReadOnlyList<string> DropEvidence { get; init; } = [];

    public bool ConnectedToDirectIpWithoutDns { get; init; }
    public bool ContactedKnownDeadDrop { get; init; }
    public IReadOnlyList<string> NetworkEvidence { get; init; } = [];

    public bool IsFirstRunOfBinary { get; init; }
    public bool InstalledPersistence { get; init; }
    public IReadOnlyList<string> PersistenceEvidence { get; init; } = [];

    public bool SelfDeleted { get; init; }
    public bool BeaconingDetected { get; init; }
    public string? BeaconingEvidence { get; init; }
    public bool HiddenWindowWithActiveNetwork { get; init; }

    public bool LoadedUnsignedModuleInTrustedProcess { get; init; }
    public IReadOnlyList<string> ModuleEvidence { get; init; } = [];

    public bool SignerHasEstablishedLocalReputation { get; init; }
    public int LocalPrevalenceRunCount { get; init; }
    public bool UserMarkedTrusted { get; init; }
    /// <summary>Hash mudou desde a marcação de confiança. Reativa o score.</summary>
    public bool HashChangedSinceTrusted { get; init; }
}

/// <summary>
/// Sistema de pontuação aditivo com pesos configuráveis, sempre exibido decomposto.
/// </summary>
public sealed class ScoreEngine(ScoreWeights? weights = null)
{
    private readonly ScoreWeights _w = weights ?? new ScoreWeights();

    public SuspicionScore Compute(ScoringFacts facts)
    {
        var signals = new List<Signal>();
        var reducers = new List<Signal>();
        var exec = facts.Execution;
        var sig = exec.Binary.Signature;

        if (sig.Status is SignatureStatus.SignedInvalid or SignatureStatus.SignedRevoked)
        {
            var why = sig.Status == SignatureStatus.SignedInvalid
                ? "The file hash does not match the signature: the binary was altered after it was signed."
                : "The certificate that signed this binary has been revoked - often a stolen certificate used by malware.";
            Add(signals, SignalKind.InvalidOrRevokedSignature, _w.InvalidOrRevokedSignature,
                "Invalid signature or revoked certificate", why, [exec.Binary.Path]);
        }

        if (facts.Masquerading is { Any: true } masq)
        {
            Add(signals, SignalKind.Masquerading, _w.Masquerading,
                "Masquerading (tries to pass for another)", masq.Summary, masq.Evidence);
        }

        if (facts.ReadCredentialDirectories)
        {
            Add(signals, SignalKind.CredentialDirectoryRead, _w.CredentialDirectoryRead,
                "Read of credential directories",
                "This process read credential vaults/wallets/tokens without being the software that owns that data - one of the strongest info-stealer signals.",
                facts.CredentialReadEvidence);
        }

        if (facts.RunsFromUserWritableDirectory && sig.Status is SignatureStatus.Unsigned or SignatureStatus.SelfSigned)
        {
            Add(signals, SignalKind.UnsignedFromWritableDir, _w.UnsignedFromWritableDir,
                "Unsigned in a writable directory",
                "Unsigned binary running from a user-writable directory (%TEMP%, Downloads, AppData) - legitimate software rarely combines the two.",
                [exec.Binary.Path]);
        }

        if (facts.ShortLived && facts.UploadBytes > 0)
        {
            Add(signals, SignalKind.ShortLivedWithUpload, _w.ShortLivedWithUpload,
                "Short-lived with external upload",
                $"The process lived for {FormatDuration(exec.Duration)} and uploaded {FormatBytes(facts.UploadBytes)} externally - a classic one-shot exfiltration signature.",
                facts.NetworkEvidence);
        }

        if (facts.DroppedExecutableLaterExecuted)
        {
            Add(signals, SignalKind.DropAndExecute, _w.DropAndExecute,
                "Executable drop followed by execution",
                "This process created an executable on disk that was later executed - typical dropper behavior.",
                facts.DropEvidence);
        }

        if (facts.ConnectedToDirectIpWithoutDns || facts.ContactedKnownDeadDrop)
        {
            var why = facts.ConnectedToDirectIpWithoutDns
                ? "Direct connection to an IP without a prior DNS lookup - C2 with a fixed address is a common pattern."
                : "Destination on a service frequently abused for exfiltration (dead drop). Not a verdict: the service itself is legitimate.";
            Add(signals, SignalKind.DirectIpOrDeadDrop, _w.DirectIpOrDeadDrop,
                "Direct IP connection without DNS / \"dead drop\" destination", why, facts.NetworkEvidence);
        }

        if (facts.CommandLine is { Suspicious: true } cl)
        {
            Add(signals, SignalKind.ObfuscatedCommandLineOrLolbin, _w.ObfuscatedCommandLineOrLolbin,
                "Obfuscated command line / anomalous LOLBin", cl.Summary, [exec.CommandLine ?? string.Empty]);
        }

        if (exec.Binary.Motw is { FromInternet: true } && facts.IsFirstRunOfBinary)
        {
            Add(signals, SignalKind.MotwPresentFirstRun, _w.MotwPresentFirstRun,
                "Mark of the Web on first run",
                $"The file came from the internet (zone {exec.Binary.Motw.ZoneId}{(exec.Binary.Motw.HostUrl is { } h ? $", origin {h}" : string.Empty)}) and this is its first run.",
                [exec.Binary.Path]);
        }

        if (IsUnlikelyParent(exec))
        {
            Add(signals, SignalKind.UnlikelyParent, _w.UnlikelyParent,
                "Unlikely parent",
                $"Launched by {System.IO.Path.GetFileName(exec.CreatorImage ?? exec.DeclaredParentImage ?? "?")} - Office/browser/PDF reader spawning a shell or script is a macro/exploit classic.",
                [exec.CreatorImage ?? string.Empty]);
        }

        if (facts.InstalledPersistence && facts.IsFirstRunOfBinary)
        {
            Add(signals, SignalKind.PersistenceOnFirstRun, _w.PersistenceOnFirstRun,
                "Persistence installed on first run",
                "On its very first run the binary installed an auto-start mechanism - eager to survive reboots.",
                facts.PersistenceEvidence);
        }

        if (facts.IsFirstRunOfBinary)
        {
            Add(signals, SignalKind.NeverSeenBinary, _w.NeverSeenBinary,
                "Never-seen binary (novelty)",
                "First run of this binary on this machine since monitoring began. Novelty is not guilt - but it amplifies other signals.",
                [exec.Binary.Sha256 ?? exec.Binary.Path]);
        }

        if (facts.SelfDeleted)
        {
            Add(signals, SignalKind.SelfDeletion, _w.SelfDeletion,
                "Self-deletion after execution",
                "The binary file disappeared seconds after it exited - typical anti-forensics. The dossier preserves the hash and metadata.",
                [exec.Binary.Path]);
        }

        if (facts.BeaconingDetected)
        {
            Add(signals, SignalKind.PeriodicBeaconing, _w.PeriodicBeaconing,
                "Periodic beaconing",
                facts.BeaconingEvidence ?? "Periodic connections with a regular interval and a small payload - a beacon pattern.",
                facts.NetworkEvidence);
        }

        if (facts.HiddenWindowWithActiveNetwork)
        {
            Add(signals, SignalKind.HiddenWindowWithNetwork, _w.HiddenWindowWithNetwork,
                "Hidden window with active network",
                "The process runs with no visible window and keeps up network communication.",
                facts.NetworkEvidence);
        }

        if (facts.LoadedUnsignedModuleInTrustedProcess)
        {
            Add(signals, SignalKind.UnsignedModuleInTrustedProcess, _w.UnsignedModuleInTrustedProcess,
                "Unsigned DLL in a trusted process",
                "An unsigned module from a writable directory was loaded into a signed/trusted process - covers DLL sideloading and part of the injection cases.",
                facts.ModuleEvidence);
        }

        if (facts.SignerHasEstablishedLocalReputation && sig.Status == SignatureStatus.SignedTrusted)
        {
            Add(reducers, SignalKind.ReputableSignerEstablished, _w.ReducerReputableSigner,
                "Signer with established local reputation",
                $"Binaries signed by \"{sig.Subject}\" have run on this machine for a while without incident.", []);
        }

        if (facts.LocalPrevalenceRunCount >= 20)
        {
            Add(reducers, SignalKind.HighLocalPrevalence, _w.ReducerHighPrevalence,
                "High local prevalence",
                $"This binary has already run {facts.LocalPrevalenceRunCount} times on this machine - info-stealers typically run only once.", []);
        }

        var total = Math.Max(0, signals.Sum(s => s.Weight) + reducers.Sum(r => r.Weight));

        // Confiança manual silencia, mas hash mudado reativa.
        var muted = facts.UserMarkedTrusted && !facts.HashChangedSinceTrusted;

        return new SuspicionScore { Total = total, Signals = signals, Reducers = reducers, Muted = muted };
    }

    private static void Add(List<Signal> list, SignalKind kind, int weight, string title, string explanation, IReadOnlyList<string> evidence)
    {
        if (weight == 0) return;
        list.Add(new Signal { Kind = kind, Weight = weight, Title = title, Explanation = explanation, Evidence = evidence });
    }

    /// <summary>Office/navegador/leitor de PDF disparando shell, script ou binário de diretório gravável.</summary>
    public static bool IsUnlikelyParent(ProcessExecution exec)
    {
        var parent = System.IO.Path.GetFileName(exec.CreatorImage ?? exec.DeclaredParentImage ?? string.Empty).ToLowerInvariant();
        if (parent.Length == 0) return false;
        var child = exec.Binary.FileName.ToLowerInvariant();

        bool parentIsDocApp = Catalog.CuratedLists.Default.DocumentHostProcesses.Contains(parent);
        bool childIsShellOrScript = Catalog.CuratedLists.Default.ShellAndScriptHosts.Contains(child);
        return parentIsDocApp && childIsShellOrScript;
    }

    public static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024 * 1024):0.#} GB",
        >= 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} MB",
        >= 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes} B",
    };

    public static string FormatDuration(TimeSpan? d) => d switch
    {
        null => "still running",
        { TotalSeconds: < 1 } => "less than 1s",
        { TotalSeconds: < 60 } ts => $"{ts.TotalSeconds:0.#}s",
        { TotalMinutes: < 60 } ts => $"{(int)ts.TotalMinutes}min {ts.Seconds}s",
        { } ts => $"{(int)ts.TotalHours}h {ts.Minutes}min",
    };
}
