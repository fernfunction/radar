using Radar.Core.Analysis;

namespace Radar.Core.Model;

/// <summary>Contexto de segurança da execução: "quem".</summary>
public sealed record SecurityContext
{
    public string? UserName { get; init; }
    public string? UserSid { get; init; }
    public AccountKind AccountKind { get; init; } = AccountKind.Unknown;
    public IntegrityLevel IntegrityLevel { get; init; } = IntegrityLevel.Unknown;
    /// <summary>Houve elevação (UAC).</summary>
    public bool Elevated { get; init; }
    public int SessionId { get; init; }
    public bool IsInteractiveSession => SessionId > 0;
    /// <summary>Processo tem janela visível ou roda oculto.</summary>
    public bool? HasVisibleWindow { get; init; }
}

/// <summary>Um elo da cadeia de ancestralidade, capturado no momento da criação.</summary>
public sealed record AncestryLink(int Pid, string? ImagePath, DateTimeOffset? StartedUtc);

/// <summary>Atribuição semântica do mecanismo de disparo.</summary>
public sealed record OriginAttribution
{
    public LaunchOrigin Origin { get; init; } = LaunchOrigin.Unknown;
    /// <summary>Frase legível: "Disparado pelo Agendador de Tarefas, tarefa \Microsoft\...\X".</summary>
    public required string Description { get; init; }
    /// <summary>Nome da tarefa/serviço/chave quando aplicável.</summary>
    public string? MechanismName { get; init; }
    /// <summary>Data de instalação do mecanismo (serviço/tarefa/chave), quando conhecida.</summary>
    public DateTimeOffset? MechanismInstalledUtc { get; init; }
    /// <summary>O pai terminou antes do filho.</summary>
    public bool ParentDiedBeforeChild { get; init; }
    /// <summary>Criador real difere do pai declarado (parent PID spoofing).</summary>
    public bool ParentForged { get; init; }
}

/// <summary>
/// O Dossiê de Processo: uma EXECUÇÃO (não um binário) com todo o contexto.
/// Reconstruível do histórico mesmo após a morte do processo.
/// </summary>
public sealed record ProcessExecution
{
    public required Guid ExecutionId { get; init; }
    public required int Pid { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset? ExitedUtc { get; init; }
    public int? ExitCode { get; init; }
    public string? CommandLine { get; init; }
    public required BinaryIdentity Binary { get; init; }
    public SecurityContext Security { get; init; } = new();

    // Pai declarado e criador real. Divergência = parent spoofing.
    public int DeclaredParentPid { get; init; }
    public string? DeclaredParentImage { get; init; }
    public int CreatorPid { get; init; }
    public string? CreatorImage { get; init; }
    public Guid? ParentExecutionId { get; init; }
    /// <summary>Snapshot da cadeia de ancestralidade (os pais podem morrer).</summary>
    public IReadOnlyList<AncestryLink> Ancestry { get; init; } = [];
    public OriginAttribution? Origin { get; init; }

    public SuspicionScore? Score { get; init; }
    public UserVerdict Verdict { get; init; } = UserVerdict.None;
    public string? UserNotes { get; init; }

    /// <summary>Contagem de execuções do mesmo binário até esta (prevalência local).</summary>
    public int PriorRunCountSameBinary { get; init; }

    public TimeSpan? Duration => ExitedUtc is { } e ? e - CreatedUtc : null;
    public bool IsAlive => ExitedUtc is null;

    public bool IsShortLived(TimeSpan threshold) => Duration is { } d && d <= threshold;

    /// <summary>Faixa visual de vida curta: &lt;1s, 1-5s, 5-30s.</summary>
    public ShortLivedBand? ShortLivedBand(TimeSpan threshold)
    {
        if (Duration is not { } d || d > threshold) return null;
        if (d < TimeSpan.FromSeconds(1)) return Model.ShortLivedBand.SubSecond;
        if (d <= TimeSpan.FromSeconds(5)) return Model.ShortLivedBand.OneToFive;
        return Model.ShortLivedBand.FiveToThreshold;
    }
}

public enum ShortLivedBand
{
    SubSecond = 0,
    OneToFive = 1,
    FiveToThreshold = 2,
}
