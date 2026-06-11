using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Core.Tests;

public class ShortLivedAnalyzerTests
{
    private static readonly ShortLivedAnalyzer Analyzer = new();
    private static readonly TimeSpan Threshold = TimeSpan.FromSeconds(30);

    [Fact]
    public void Groups_by_binary_and_computes_stats()
    {
        var start = new DateTimeOffset(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);
        var executions = Enumerable.Range(0, 10).Select(i => TestData.Execution(
            path: @"C:\Temp\beacon.exe",
            created: start.AddMinutes(i * 5), // intervalo perfeitamente regular
            duration: TimeSpan.FromSeconds(2),
            sha256: "FFFF"))
            .ToList();

        var view = Analyzer.Build(executions, Threshold);

        var group = Assert.Single(view.Groups);
        Assert.Equal(10, group.Count);
        // Regularidade extrema é, por si, um sinal
        Assert.True(group.SuspiciouslyRegular);
        Assert.NotNull(group.MeanInterval);
        Assert.Equal(TimeSpan.FromMinutes(5), group.MeanInterval!.Value);
    }

    [Fact]
    public void Irregular_executions_not_flagged_as_regular()
    {
        var start = new DateTimeOffset(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);
        var offsets = new[] { 0, 3, 11, 12, 29, 50, 51, 90 };
        var executions = offsets.Select(min => TestData.Execution(
            created: start.AddMinutes(min), duration: TimeSpan.FromSeconds(1), sha256: "EEEE")).ToList();

        var view = Analyzer.Build(executions, Threshold);
        Assert.False(Assert.Single(view.Groups).SuspiciouslyRegular);
    }

    [Fact]
    public void Long_lived_executions_are_excluded()
    {
        var executions = new[]
        {
            TestData.Execution(duration: TimeSpan.FromMinutes(10), sha256: "1111"),
            TestData.Execution(duration: TimeSpan.FromSeconds(3), sha256: "2222"),
        };
        var view = Analyzer.Build(executions, Threshold);
        Assert.Single(view.Groups);
    }

    [Fact]
    public void Legit_ephemeral_suppressed_with_visible_counter()
    {
        // Supressão sempre por assinatura+caminho
        var conhost = TestData.Execution(
            path: @"C:\Windows\System32\conhost.exe",
            signature: SignatureStatus.SignedTrusted,
            isMicrosoftRoot: true,
            duration: TimeSpan.FromSeconds(1),
            sha256: "C0C0");

        var view = Analyzer.Build([conhost], Threshold);
        Assert.Empty(view.Groups);
        Assert.Equal(1, view.SuppressedExecutionCount);

        // Mesmo nome, sem assinatura: NÃO suprime
        var fake = TestData.Execution(
            path: @"C:\Temp\conhost.exe",
            signature: SignatureStatus.Unsigned,
            duration: TimeSpan.FromSeconds(1),
            sha256: "BAD0");
        var view2 = Analyzer.Build([fake], Threshold);
        Assert.Single(view2.Groups);
        Assert.Equal(0, view2.SuppressedExecutionCount);
    }

    [Fact]
    public void Ephemeral_chains_are_found()
    {
        var start = new DateTimeOffset(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);
        var a = TestData.Execution(path: @"C:\Temp\a.exe", created: start,
            duration: TimeSpan.FromSeconds(5), sha256: "AA00");
        var b = TestData.Execution(path: @"C:\Temp\b.exe", created: start.AddSeconds(1),
            duration: TimeSpan.FromSeconds(3), sha256: "BB00") with
        { ParentExecutionId = a.ExecutionId };
        var c = TestData.Execution(path: @"C:\Temp\c.exe", created: start.AddSeconds(2),
            duration: TimeSpan.FromSeconds(2), sha256: "CC00") with
        { ParentExecutionId = b.ExecutionId };

        var chains = ShortLivedAnalyzer.FindEphemeralChains([a, b, c], Threshold);
        var chain = Assert.Single(chains);
        Assert.Equal(3, chain.Count);
        Assert.Equal(a.ExecutionId, chain[0].ExecutionId);
        Assert.Equal(c.ExecutionId, chain[2].ExecutionId);
    }
}

public class BeaconingDetectorTests
{
    private static NetworkConnection Conn(DateTimeOffset at, long sent = 512, long received = 256,
        string domain = "c2.example.com") => new()
    {
        ExecutionId = Guid.Empty,
        FirstSeenUtc = at,
        Protocol = NetworkProtocol.Tcp,
        RemoteAddress = "203.0.113.7",
        RemotePort = 443,
        BytesSent = sent,
        BytesReceived = received,
        ResolvedFromDomain = domain,
    };

    [Fact]
    public void Regular_small_connections_are_beaconing()
    {
        var start = new DateTimeOffset(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);
        var connections = Enumerable.Range(0, 8).Select(i => Conn(start.AddSeconds(i * 60))).ToList();

        var findings = new BeaconingDetector().Analyze(connections);
        var finding = Assert.Single(findings);
        Assert.Equal(60, finding.MeanInterval.TotalSeconds, 1);
        Assert.Contains("beacon", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Irregular_intervals_are_not_beaconing()
    {
        var start = new DateTimeOffset(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);
        var offsets = new[] { 0, 13, 200, 230, 600, 1900, 1960, 4000 };
        var connections = offsets.Select(s => Conn(start.AddSeconds(s))).ToList();
        Assert.Empty(new BeaconingDetector().Analyze(connections));
    }

    [Fact]
    public void Large_payloads_are_not_beaconing()
    {
        var start = new DateTimeOffset(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);
        var connections = Enumerable.Range(0, 8)
            .Select(i => Conn(start.AddSeconds(i * 60), sent: 10_000_000)).ToList();
        Assert.Empty(new BeaconingDetector().Analyze(connections));
    }

    [Fact]
    public void Too_few_connections_ignored()
    {
        var start = new DateTimeOffset(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);
        var connections = Enumerable.Range(0, 3).Select(i => Conn(start.AddSeconds(i * 60))).ToList();
        Assert.Empty(new BeaconingDetector().Analyze(connections));
    }
}
