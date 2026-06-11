namespace Radar.Core.Model;

/// <summary>Conexão de rede atribuída a uma execução. Válida mesmo após a morte do processo.</summary>
public sealed record NetworkConnection
{
    public required Guid ExecutionId { get; init; }
    public required DateTimeOffset FirstSeenUtc { get; init; }
    public DateTimeOffset? LastSeenUtc { get; init; }
    public NetworkProtocol Protocol { get; init; }
    public required string RemoteAddress { get; init; }
    public int RemotePort { get; init; }
    public int LocalPort { get; init; }
    public long BytesSent { get; init; }
    public long BytesReceived { get; init; }
    /// <summary>Domínio que originou o IP via correlação DNS→conexão; null = IP direto sem DNS prévio.</summary>
    public string? ResolvedFromDomain { get; init; }
}

/// <summary>Consulta DNS por execução.</summary>
public sealed record DnsQuery
{
    public required Guid ExecutionId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string Domain { get; init; }
    public IReadOnlyList<string> ResolvedAddresses { get; init; } = [];
}

/// <summary>Evento de arquivo em escopo monitorado.</summary>
public sealed record FileActivity
{
    public required Guid ExecutionId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public required FileEventKind Kind { get; init; }
    public required string Path { get; init; }
    /// <summary>Hash do arquivo dropado (linhagem: quem criou o quê).</summary>
    public string? Sha256 { get; init; }
    /// <summary>Categoria sensível (ex.: "Cofre de credenciais do Chrome", "Carteira de criptomoedas").</summary>
    public string? SensitiveCategory { get; init; }
}

/// <summary>Módulo/DLL carregado digno de nota.</summary>
public sealed record ModuleLoad
{
    public required Guid ExecutionId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string ModulePath { get; init; }
    public SignatureStatus SignatureStatus { get; init; } = SignatureStatus.Unknown;
    /// <summary>Carregado de diretório gravável pelo usuário (%TEMP%, AppData...).</summary>
    public bool FromUserWritableDirectory { get; init; }
    /// <summary>Processo hospedeiro é assinado/confiável. DLL não assinada aqui é o sinal de sideloading.</summary>
    public bool HostIsTrusted { get; init; }
}

/// <summary>Amostra de consumo de recursos.</summary>
public sealed record ResourceSample
{
    public required Guid ExecutionId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public double CpuPercent { get; init; }
    public long WorkingSetBytes { get; init; }
    public long IoBytesPerSecond { get; init; }
}

/// <summary>Marcador de contexto do sistema na timeline.</summary>
public sealed record SystemMarker
{
    public required DateTimeOffset TimestampUtc { get; init; }
    public required SystemMarkerKind Kind { get; init; }
    public string? Detail { get; init; }
}

/// <summary>
/// Evento unificado para a timeline: criação/término, primeira conexão,
/// drop de executável, persistência instalada, primeira execução de binário novo.
/// </summary>
public sealed record TimelineEvent
{
    public required DateTimeOffset TimestampUtc { get; init; }
    public required TimelineEventKind Kind { get; init; }
    public Guid? ExecutionId { get; init; }
    public required string Title { get; init; }
    public string? Detail { get; init; }
    public int Score { get; init; }
}

public enum TimelineEventKind
{
    ProcessStart = 0,
    ProcessEnd = 1,
    FirstNetworkConnection = 2,
    ExecutableDrop = 3,
    PersistenceInstalled = 4,
    FirstRunOfNewBinary = 5,
    SystemMarker = 6,
    SensitiveRead = 7,
    SelfDelete = 8,
}
