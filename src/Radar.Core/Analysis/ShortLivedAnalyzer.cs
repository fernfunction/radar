using Radar.Core.Catalog;
using Radar.Core.Model;

namespace Radar.Core.Analysis;

/// <summary>
/// Grupo de execuções do mesmo binário na vista Short-Lived:
/// 200 execuções viram uma linha expansível com estatísticas.
/// </summary>
public sealed record ShortLivedGroup
{
    public required string BinaryKey { get; init; }
    public required string DisplayName { get; init; }
    public required string ImagePath { get; init; }
    public IReadOnlyList<ProcessExecution> Executions { get; init; } = [];
    public int Count => Executions.Count;
    public DateTimeOffset FirstUtc { get; init; }
    public DateTimeOffset LastUtc { get; init; }
    public int MaxScore { get; init; }
    public long TotalUploadBytes { get; init; }

    /// <summary>Coeficiente de variação dos intervalos entre execuções. Perto de 0 = regularidade extrema.</summary>
    public double? IntervalRegularity { get; init; }
    /// <summary>Intervalo médio entre execuções.</summary>
    public TimeSpan? MeanInterval { get; init; }
    /// <summary>Regularidade extrema de intervalo é, por si, um sinal (tarefa oculta? beacon?).</summary>
    public bool SuspiciouslyRegular => IntervalRegularity is { } cv && cv < 0.15 && Count >= 5;
    /// <summary>Quantas variações distintas de linha de comando o grupo tem.</summary>
    public int CommandLineVariants { get; init; }
    /// <summary>Grupo suprimido como efêmero legítimo (mantém contador para auditabilidade).</summary>
    public bool Suppressed { get; init; }
}

public sealed record ShortLivedView
{
    public IReadOnlyList<ShortLivedGroup> Groups { get; init; } = [];
    /// <summary>"X execuções suprimidas": auditabilidade da supressão.</summary>
    public int SuppressedExecutionCount { get; init; }
    public int SuppressedGroupCount { get; init; }
}

/// <summary>
/// Visibilidade sobre processos que existem por segundos e desaparecem.
/// Agrupa por binário, calcula estatísticas de frequência/regularidade e aplica supressão auditável.
/// </summary>
public sealed class ShortLivedAnalyzer(CuratedLists? lists = null)
{
    private readonly CuratedLists _lists = lists ?? CuratedLists.Default;

    /// <param name="threshold">"Vida curta" configurável. Padrão sugerido &lt; 30s.</param>
    /// <param name="uploadByExecution">Bytes enviados por execução (para ordenar por volume de rede).</param>
    /// <param name="includeSuppressed">Modo auditoria: mostra também os suprimidos.</param>
    public ShortLivedView Build(
        IEnumerable<ProcessExecution> executions,
        TimeSpan threshold,
        IReadOnlyDictionary<Guid, long>? uploadByExecution = null,
        bool includeSuppressed = false)
    {
        var shortLived = executions.Where(e => e.IsShortLived(threshold)).ToList();

        var groups = new List<ShortLivedGroup>();
        int suppressedExecs = 0, suppressedGroups = 0;

        foreach (var byBinary in shortLived.GroupBy(BinaryKey))
        {
            var ordered = byBinary.OrderBy(e => e.CreatedUtc).ToList();
            var sample = ordered[^1];

            var intervals = new List<double>();
            for (var i = 1; i < ordered.Count; i++)
                intervals.Add((ordered[i].CreatedUtc - ordered[i - 1].CreatedUtc).TotalSeconds);

            double? regularity = null;
            TimeSpan? meanInterval = null;
            if (intervals.Count >= 2)
            {
                var mean = intervals.Average();
                if (mean > 0)
                {
                    var std = Math.Sqrt(intervals.Sum(x => (x - mean) * (x - mean)) / intervals.Count);
                    regularity = std / mean;
                    meanInterval = TimeSpan.FromSeconds(mean);
                }
            }

            bool suppressed = IsSuppressible(sample);
            if (suppressed)
            {
                suppressedExecs += ordered.Count;
                suppressedGroups++;
                if (!includeSuppressed) continue;
            }

            groups.Add(new ShortLivedGroup
            {
                BinaryKey = byBinary.Key,
                DisplayName = sample.Binary.FileName,
                ImagePath = sample.Binary.Path,
                Executions = ordered,
                FirstUtc = ordered[0].CreatedUtc,
                LastUtc = ordered[^1].CreatedUtc,
                MaxScore = ordered.Max(e => e.Score?.Muted == true ? 0 : e.Score?.Total ?? 0),
                TotalUploadBytes = uploadByExecution is null
                    ? 0
                    : ordered.Sum(e => uploadByExecution.GetValueOrDefault(e.ExecutionId)),
                IntervalRegularity = regularity,
                MeanInterval = meanInterval,
                CommandLineVariants = ordered.Select(e => e.CommandLine ?? string.Empty)
                                             .Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                Suppressed = suppressed,
            });
        }

        return new ShortLivedView
        {
            // Ordenável por recência, score, volume de rede, repetições. Padrão: score, depois recência.
            Groups = groups.OrderByDescending(g => g.MaxScore).ThenByDescending(g => g.LastUtc).ToList(),
            SuppressedExecutionCount = suppressedExecs,
            SuppressedGroupCount = suppressedGroups,
        };
    }

    /// <summary>
    /// Supressão de efêmeros legítimos e frequentes: sempre por assinatura+caminho, nunca só nome.
    /// </summary>
    public bool IsSuppressible(ProcessExecution exec)
    {
        if (!_lists.KnownEphemeralProcesses.Contains(exec.Binary.FileName)) return false;
        if (exec.Binary.Signature.Status != SignatureStatus.SignedTrusted) return false;
        var dir = (Path.GetDirectoryName(exec.Binary.Path) ?? string.Empty).ToLowerInvariant();
        return dir.Contains(@"\windows\") || dir.Contains(@"\program files") ||
               dir.EndsWith(@"\windows", StringComparison.OrdinalIgnoreCase);
    }

    private static string BinaryKey(ProcessExecution e) =>
        e.Binary.Sha256 ?? e.Binary.Path.ToLowerInvariant();

    /// <summary>
    /// Cadeias curtas de processos efêmeros: A (5s) cria B, B (3s) cria C.
    /// Retorna cadeias com 2+ elos para desenhar como grafo compacto.
    /// </summary>
    public static IReadOnlyList<IReadOnlyList<ProcessExecution>> FindEphemeralChains(
        IReadOnlyCollection<ProcessExecution> executions, TimeSpan threshold)
    {
        var byId = executions.ToDictionary(e => e.ExecutionId);
        var shortOnes = executions.Where(e => e.IsShortLived(threshold)).ToList();
        var childrenOf = shortOnes
            .Where(e => e.ParentExecutionId is { } p && byId.ContainsKey(p))
            .ToLookup(e => e.ParentExecutionId!.Value);

        var chains = new List<IReadOnlyList<ProcessExecution>>();
        var roots = shortOnes.Where(e =>
            e.ParentExecutionId is not { } p || !byId.TryGetValue(p, out var parent) || !parent.IsShortLived(threshold));

        foreach (var root in roots)
        {
            var chain = new List<ProcessExecution> { root };
            var current = root;
            while (childrenOf[current.ExecutionId].FirstOrDefault() is { } child)
            {
                chain.Add(child);
                current = child;
            }
            if (chain.Count >= 2) chains.Add(chain);
        }
        return chains;
    }
}
