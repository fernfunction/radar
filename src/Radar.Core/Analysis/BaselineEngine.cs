using Radar.Core.Model;

namespace Radar.Core.Analysis;

/// <summary>O que é "normal" NESTA máquina: hashes, emissores, destinos, persistências.</summary>
public sealed record BaselineState
{
    public DateTimeOffset LearningStartedUtc { get; init; }
    public required TimeSpan LearningPeriod { get; init; }
    public HashSet<string> KnownBinaryHashes { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> KnownSignerSubjects { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> KnownDomains { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> KnownPersistenceIds { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Prevalência local: hash → (contagem de execuções, primeira vez visto).</summary>
    public Dictionary<string, PrevalenceInfo> Prevalence { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public bool LearningComplete(DateTimeOffset now) => now - LearningStartedUtc >= LearningPeriod;
}

/// <summary>Prevalência local de um binário. Serializável.</summary>
public sealed record PrevalenceInfo(int RunCount, DateTimeOffset FirstSeenUtc);

/// <summary>Atributos de novidade de uma execução; multiplica outros sinais no score.</summary>
public sealed record NoveltyAttributes
{
    public bool FirstRunOfBinary { get; init; }
    public bool FirstContactWithDomain { get; init; }
    public bool FirstSignerSeen { get; init; }
    public bool NewPersistence { get; init; }
    public int PrevalenceRunCount { get; init; }
    public DateTimeOffset? BinaryFirstSeenUtc { get; init; }
}

/// <summary>
/// Baseline e novidade: período de aprendizado inicial (padrão 7 dias) construindo a
/// base do normal; depois, tudo ganha atributo de novidade e prevalência local.
/// </summary>
public sealed class BaselineEngine
{
    public static TimeSpan DefaultLearningPeriod => TimeSpan.FromDays(7);

    /// <summary>Avalia novidade de uma execução contra o estado de baseline, sem mutá-lo.</summary>
    public NoveltyAttributes Evaluate(BaselineState state, ProcessExecution exec,
        IEnumerable<string>? contactedDomains = null, IEnumerable<string>? newPersistenceIds = null)
    {
        var hash = exec.Binary.Sha256;
        var prevalence = hash is not null && state.Prevalence.TryGetValue(hash, out var p) ? p : null;

        return new NoveltyAttributes
        {
            FirstRunOfBinary = hash is not null && !state.KnownBinaryHashes.Contains(hash),
            FirstSignerSeen = exec.Binary.Signature.Subject is { } subject &&
                              !state.KnownSignerSubjects.Contains(subject),
            FirstContactWithDomain = contactedDomains?.Any(d => !state.KnownDomains.Contains(d)) ?? false,
            NewPersistence = newPersistenceIds?.Any(id => !state.KnownPersistenceIds.Contains(id)) ?? false,
            PrevalenceRunCount = prevalence?.RunCount ?? 0,
            BinaryFirstSeenUtc = prevalence?.FirstSeenUtc,
        };
    }

    /// <summary>Absorve uma execução no baseline (chamado após avaliar novidade).</summary>
    public void Absorb(BaselineState state, ProcessExecution exec,
        IEnumerable<string>? contactedDomains = null, IEnumerable<string>? persistenceIds = null)
    {
        if (exec.Binary.Sha256 is { } hash)
        {
            state.KnownBinaryHashes.Add(hash);
            state.Prevalence[hash] = state.Prevalence.TryGetValue(hash, out var p)
                ? p with { RunCount = p.RunCount + 1 }
                : new PrevalenceInfo(1, exec.CreatedUtc);
        }
        if (exec.Binary.Signature.Subject is { } subject)
            state.KnownSignerSubjects.Add(subject);
        foreach (var d in contactedDomains ?? [])
            state.KnownDomains.Add(d);
        foreach (var id in persistenceIds ?? [])
            state.KnownPersistenceIds.Add(id);
    }

    /// <summary>
    /// O emissor tem "reputação local estabelecida": visto há mais de 30 dias
    /// assinando 3+ binários distintos confiáveis.
    /// </summary>
    public static bool SignerHasEstablishedReputation(
        IReadOnlyCollection<(string Subject, DateTimeOffset FirstSeen, int DistinctBinaries)> signerStats,
        string? subject, DateTimeOffset now)
    {
        if (subject is null) return false;
        var stat = signerStats.FirstOrDefault(s => s.Subject.Equals(subject, StringComparison.OrdinalIgnoreCase));
        return stat != default && now - stat.FirstSeen > TimeSpan.FromDays(30) && stat.DistinctBinaries >= 3;
    }
}
