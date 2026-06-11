using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Collector;

/// <summary>
/// Dossiê "ao vivo" de uma execução: acumula fatos enquanto o processo roda, para que o dossiê
/// completo exista mesmo que o processo morra em segundos. Gravador contínuo.
/// </summary>
public sealed class ExecutionTracker
{
    private readonly object _lock = new();

    public ExecutionTracker(ProcessExecution initial) => Execution = initial;

    public ProcessExecution Execution { get; private set; }
    public Guid ExecutionId => Execution.ExecutionId;
    public bool Dirty { get; set; }
    /// <summary>Identidade (hash/MOTW/versão) já enriquecida.</summary>
    public bool IdentityEnriched { get; set; }
    public DateTimeOffset? ExitObservedUtc { get; private set; }

    public sealed class ConnAgg
    {
        public DateTimeOffset FirstSeenUtc;
        public DateTimeOffset LastSeenUtc;
        public long BytesSent;
        public long BytesReceived;
        public string? Domain;
        public bool Stored;
    }

    public Dictionary<(string Addr, int Port, NetworkProtocol Proto), ConnAgg> Connections { get; } = [];
    public HashSet<string> Domains { get; } = new(StringComparer.OrdinalIgnoreCase);
    public long UploadBytes;
    public long DownloadBytes;
    public bool FirstConnectionLogged;
    public bool ConnectedDirectIp;
    public bool ContactedDeadDrop;
    public List<string> NetworkEvidence { get; } = [];

    public bool ReadCredentialDirectories;
    public List<string> CredentialEvidence { get; } = [];
    public List<string> DropEvidence { get; } = [];
    public bool DroppedExecutableLaterExecuted;
    public bool SelfDeleted;
    public readonly HashSet<string> SensitiveCategoriesSeen = new(StringComparer.OrdinalIgnoreCase);
    public readonly HashSet<string> DroppedPaths = new(StringComparer.OrdinalIgnoreCase);

    public bool LoadedUnsignedModuleInTrustedProcess;
    public List<string> ModuleEvidence { get; } = [];
    public readonly HashSet<string> ModulesSeen = new(StringComparer.OrdinalIgnoreCase);

    public bool InstalledPersistence;
    public List<string> PersistenceEvidence { get; } = [];

    public bool IsFirstRunOfBinary;
    public int PriorRunCount;
    public bool SignerHasReputation;
    public bool UserMarkedTrusted;
    public bool HashChangedSinceTrusted;
    public bool BeaconingDetected;
    public string? BeaconingEvidence;

    public ScoreBand LastNotifiedBand = ScoreBand.Informational;

    public void Mutate(Func<ProcessExecution, ProcessExecution> update)
    {
        lock (_lock)
        {
            Execution = update(Execution);
            Dirty = true;
        }
    }

    public void MarkExited(DateTimeOffset whenUtc, int? exitCode)
    {
        ExitObservedUtc = whenUtc;
        Mutate(e => e with { ExitedUtc = whenUtc, ExitCode = exitCode });
    }

    /// <summary>Constrói os fatos para o motor de score a partir do estado acumulado.</summary>
    public ScoringFacts BuildFacts(MasqueradingFindings? masquerading, CommandLineFindings? commandLine)
    {
        lock (_lock)
        {
            var exec = Execution;
            return new ScoringFacts
            {
                Execution = exec,
                Masquerading = masquerading,
                CommandLine = commandLine,
                ReadCredentialDirectories = ReadCredentialDirectories,
                CredentialReadEvidence = CredentialEvidence.ToList(),
                RunsFromUserWritableDirectory = Core.Filtering.VisibilityFilter.IsUserWritableDirectory(exec.Binary.Path),
                ShortLived = exec.Duration is { TotalSeconds: <= 30 },
                UploadBytes = UploadBytes,
                DownloadBytes = DownloadBytes,
                DroppedExecutableLaterExecuted = DroppedExecutableLaterExecuted,
                DropEvidence = DropEvidence.ToList(),
                ConnectedToDirectIpWithoutDns = ConnectedDirectIp,
                ContactedKnownDeadDrop = ContactedDeadDrop,
                NetworkEvidence = NetworkEvidence.ToList(),
                IsFirstRunOfBinary = IsFirstRunOfBinary,
                InstalledPersistence = InstalledPersistence,
                PersistenceEvidence = PersistenceEvidence.ToList(),
                SelfDeleted = SelfDeleted,
                BeaconingDetected = BeaconingDetected,
                BeaconingEvidence = BeaconingEvidence,
                HiddenWindowWithActiveNetwork = exec.Security.HasVisibleWindow == false && Connections.Count > 0,
                LoadedUnsignedModuleInTrustedProcess = LoadedUnsignedModuleInTrustedProcess,
                ModuleEvidence = ModuleEvidence.ToList(),
                SignerHasEstablishedLocalReputation = SignerHasReputation,
                LocalPrevalenceRunCount = PriorRunCount,
                UserMarkedTrusted = UserMarkedTrusted,
                HashChangedSinceTrusted = HashChangedSinceTrusted,
            };
        }
    }

    /// <summary>Conexões agregadas → registros persistíveis (flush no término e periodicamente).</summary>
    public List<NetworkConnection> DrainUnstoredConnections()
    {
        lock (_lock)
        {
            var result = new List<NetworkConnection>();
            foreach (var ((addr, port, proto), agg) in Connections)
            {
                if (agg.Stored) continue;
                agg.Stored = true;
                result.Add(new NetworkConnection
                {
                    ExecutionId = ExecutionId,
                    FirstSeenUtc = agg.FirstSeenUtc,
                    LastSeenUtc = agg.LastSeenUtc,
                    Protocol = proto,
                    RemoteAddress = addr,
                    RemotePort = port,
                    LocalPort = 0,
                    BytesSent = agg.BytesSent,
                    BytesReceived = agg.BytesReceived,
                    ResolvedFromDomain = agg.Domain,
                });
            }
            return result;
        }
    }
}
