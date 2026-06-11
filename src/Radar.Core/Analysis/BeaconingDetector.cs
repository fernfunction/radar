using Radar.Core.Model;

namespace Radar.Core.Analysis;

/// <summary>Resultado da análise de beaconing para um destino.</summary>
public sealed record BeaconingFinding
{
    public required string Destination { get; init; }
    public required int ConnectionCount { get; init; }
    public required TimeSpan MeanInterval { get; init; }
    /// <summary>Coeficiente de variação dos intervalos: quanto menor, mais regular.</summary>
    public required double IntervalCv { get; init; }
    public required long MeanPayloadBytes { get; init; }
    public string Description =>
        $"{ConnectionCount} connections to {Destination} with a mean interval of {MeanInterval.TotalSeconds:0}s " +
        $"(variation {IntervalCv:P0}) and a mean payload of {MeanPayloadBytes} bytes - a pattern consistent with a beacon.";
}

/// <summary>
/// Detecção de beaconing por regularidade: conexões periódicas com intervalo regular
/// e payload pequeno, no histórico gravado.
/// </summary>
public sealed class BeaconingDetector
{
    /// <summary>Mínimo de conexões para considerar análise.</summary>
    public int MinConnections { get; init; } = 5;
    /// <summary>CV máximo do intervalo para considerar "regular".</summary>
    public double MaxIntervalCv { get; init; } = 0.20;
    /// <summary>Payload médio máximo (bytes) para o perfil "pequeno e periódico".</summary>
    public long MaxMeanPayloadBytes { get; init; } = 64 * 1024;

    public IReadOnlyList<BeaconingFinding> Analyze(IEnumerable<NetworkConnection> connections)
    {
        var findings = new List<BeaconingFinding>();

        foreach (var group in connections.GroupBy(DestinationKey))
        {
            var ordered = group.OrderBy(c => c.FirstSeenUtc).ToList();
            if (ordered.Count < MinConnections) continue;

            var intervals = new List<double>();
            for (var i = 1; i < ordered.Count; i++)
                intervals.Add((ordered[i].FirstSeenUtc - ordered[i - 1].FirstSeenUtc).TotalSeconds);

            var mean = intervals.Average();
            if (mean < 1) continue; // rajada, não beacon

            var std = Math.Sqrt(intervals.Sum(x => (x - mean) * (x - mean)) / intervals.Count);
            var cv = std / mean;
            var meanPayload = (long)ordered.Average(c => c.BytesSent + c.BytesReceived);

            if (cv <= MaxIntervalCv && meanPayload <= MaxMeanPayloadBytes)
            {
                findings.Add(new BeaconingFinding
                {
                    Destination = group.Key,
                    ConnectionCount = ordered.Count,
                    MeanInterval = TimeSpan.FromSeconds(mean),
                    IntervalCv = cv,
                    MeanPayloadBytes = meanPayload,
                });
            }
        }

        return findings;
    }

    private static string DestinationKey(NetworkConnection c) =>
        c.ResolvedFromDomain ?? $"{c.RemoteAddress}:{c.RemotePort}";
}
