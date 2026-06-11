namespace Radar.Core.Model;

/// <summary>Taxonomia de estados de assinatura exibida ao usuário.</summary>
public enum SignatureStatus
{
    /// <summary>Ainda não verificado (fila de verificação).</summary>
    Unknown = 0,
    /// <summary>Cadeia válida até raiz confiável, sem revogação (inclui assinatura por catálogo).</summary>
    SignedTrusted = 1,
    /// <summary>Assinado, mas com ressalvas (expirado sem timestamp, cadeia incompleta, emissor incomum).</summary>
    SignedWithCaveats = 2,
    /// <summary>Hash do arquivo não bate com a assinatura: binário alterado após assinado. Destaque máximo.</summary>
    SignedInvalid = 3,
    /// <summary>Certificado revogado, frequentemente certificado roubado. Destaque máximo.</summary>
    SignedRevoked = 4,
    /// <summary>Auto-assinado.</summary>
    SelfSigned = 5,
    /// <summary>Não assinado.</summary>
    Unsigned = 6,
}

/// <summary>Nível de integridade do token.</summary>
public enum IntegrityLevel
{
    Unknown = 0,
    Untrusted = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    System = 5,
}

/// <summary>Tipo de conta dona do token.</summary>
public enum AccountKind
{
    Unknown = 0,
    InteractiveUser = 1,
    System = 2,
    LocalService = 3,
    NetworkService = 4,
    OtherLocalUser = 5,
    ServiceAccount = 6,
}

/// <summary>Mecanismo semântico de disparo.</summary>
public enum LaunchOrigin
{
    Unknown = 0,
    UserExplorer = 1,        // duplo clique / menu Iniciar via Explorer
    UserCommandLine = 2,     // shell interativo
    ScheduledTask = 3,
    Service = 4,
    OfficeProcess = 5,       // macro/processo do Office
    Browser = 6,
    ScriptHost = 7,          // wscript/cscript/mshta executando script
    Wmi = 8,
    RunKeyOrStartup = 9,     // chave de inicialização / pasta Startup
    Orphaned = 10,           // pai morreu antes do filho
    ForgedParent = 11,       // criador real difere do pai declarado
    SystemComponent = 12,
}

/// <summary>Faixas de apresentação do score.</summary>
public enum ScoreBand
{
    /// <summary>0-24.</summary>
    Informational = 0,
    /// <summary>25-49.</summary>
    Attention = 1,
    /// <summary>50-79.</summary>
    Suspicious = 2,
    /// <summary>80+.</summary>
    Critical = 3,
}

/// <summary>Anotação manual do usuário sobre uma execução/binário.</summary>
public enum UserVerdict
{
    None = 0,
    Trusted = 1,
    Investigating = 2,
    Suspicious = 3,
}

/// <summary>Modos de visibilidade.</summary>
public enum VisibilityMode
{
    /// <summary>Apenas processos que passam pelos filtros (padrão).</summary>
    Focus = 0,
    /// <summary>Tudo, com filtros como marcação visual.</summary>
    Audit = 1,
    /// <summary>Apenas score acima de limiar configurável.</summary>
    AttentionQuarantine = 2,
}

/// <summary>Tipos de evento de arquivo monitorados seletivamente.</summary>
public enum FileEventKind
{
    Unknown = 0,
    SensitiveRead = 1,
    ExecutableDrop = 2,
    SelfDelete = 3,
    ArchiveStaging = 4,
    GenericWrite = 5,
}

/// <summary>Pontos de persistência varridos.</summary>
public enum PersistenceKind
{
    Unknown = 0,
    RunKey = 1,
    RunOnceKey = 2,
    StartupFolder = 3,
    ScheduledTask = 4,
    Service = 5,
    Ifeo = 6,
    AppInitDll = 7,
    AppCertDll = 8,
    ShellExtension = 9,
    WmiSubscription = 10,
    LsaProvider = 11,
    Winlogon = 12,
}

/// <summary>Marcadores de contexto do sistema plotados na timeline.</summary>
public enum SystemMarkerKind
{
    Unknown = 0,
    Logon = 1,
    Logoff = 2,
    ResumeFromSleep = 3,
    NetworkChange = 4,
    CollectorStarted = 5,
    CollectorStopped = 6,
    CollectorPaused = 7,
}

/// <summary>Módulos de coleta com interruptor independente.</summary>
public enum CollectionModule
{
    Processes = 0,
    Network = 1,
    Dns = 2,
    FileSensitiveReads = 3,
    FileDrops = 4,
    FileSelfDelete = 5,
    ImageLoad = 6,
    PersistenceScan = 7,
    Baseline = 8,
}

/// <summary>Direção dominante de uma conexão.</summary>
public enum NetworkProtocol
{
    Tcp = 0,
    Udp = 1,
}
