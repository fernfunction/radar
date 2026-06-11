using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Radar.App.Services;
using Radar.Core.Abstractions;

namespace Radar.App.Pages;

public sealed class NetworkRow
{
    public Guid ExecutionId { get; init; }
    public string Process { get; init; } = string.Empty;
    public string When { get; init; } = string.Empty;
    public string Destination { get; init; } = string.Empty;
    public string DomainInfo { get; init; } = string.Empty;
    public Brush DomainBrush { get; init; } = null!;
    public string Traffic { get; init; } = string.Empty;
    public string Flags { get; init; } = string.Empty;
}

public sealed class GraphEdge
{
    public string Destination { get; init; } = string.Empty;
    public string Volume { get; init; } = string.Empty;
    public double Thickness { get; init; }
}

public sealed class GraphRow
{
    public string Process { get; init; } = string.Empty;
    public Brush ScoreBrush { get; init; } = null!;
    public List<GraphEdge> Edges { get; init; } = [];
}

/// <summary>
/// Atividade de Rede por Processo: endpoints, associação DNS-conexão, marcação de IP
/// direto, upload desproporcional e grafo de comunicação com espessura por volume.
/// </summary>
public sealed partial class NetworkPage : Page
{
    public NetworkPage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void Filters_Changed(object sender, object e) => LoadData();

    private void LoadData()
    {
        if (ConnectionsList is null) return;
        TitleText.Text = I18n.T("Rede");

        var days = PeriodCombo.SelectedIndex switch { 0 => 1, 2 => 30, _ => 7 };
        var executions = AppServices.Store.QueryExecutions(new ExecutionQuery
        {
            FromUtc = DateTimeOffset.UtcNow.AddDays(-days),
            HasNetworkActivity = true,
            Limit = 2000,
        });

        var rows = new List<NetworkRow>();
        var graph = new List<GraphRow>();

        foreach (var exec in executions)
        {
            var connections = AppServices.Store.GetConnections(exec.ExecutionId);
            if (connections.Count == 0) continue;

            var score = exec.Score?.Muted == true ? 0 : exec.Score?.Total ?? 0;
            var edges = new List<GraphEdge>();
            long maxVolume = Math.Max(1, connections.Max(c => c.BytesSent + c.BytesReceived));

            foreach (var conn in connections)
            {
                bool directIp = conn.ResolvedFromDomain is null;
                bool uploadHeavy = conn.BytesSent > conn.BytesReceived && conn.BytesSent > 100_000;
                if (OnlyDirectIp.IsChecked == true && !directIp) continue;
                if (OnlyUpload.IsChecked == true && !uploadHeavy) continue;

                rows.Add(new NetworkRow
                {
                    ExecutionId = exec.ExecutionId,
                    Process = exec.Binary.FileName,
                    When = Format.Local(conn.FirstSeenUtc),
                    Destination = $"{conn.RemoteAddress}:{conn.RemotePort}/{conn.Protocol}",
                    DomainInfo = conn.ResolvedFromDomain ?? "direct IP - no prior DNS query",
                    DomainBrush = directIp
                        ? new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xCA, 0x50, 0x10))
                        : new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x90, 0x90, 0x90)),
                    Traffic = $"up {Format.Bytes(conn.BytesSent)} / down {Format.Bytes(conn.BytesReceived)}",
                    Flags = uploadHeavy ? "⚠ upload" : string.Empty,
                });

                edges.Add(new GraphEdge
                {
                    Destination = conn.ResolvedFromDomain ?? conn.RemoteAddress,
                    Volume = Format.Bytes(conn.BytesSent + conn.BytesReceived),
                    Thickness = 6 + 34.0 * (conn.BytesSent + conn.BytesReceived) / maxVolume,
                });
            }

            if (edges.Count > 0)
            {
                graph.Add(new GraphRow
                {
                    Process = exec.Binary.FileName,
                    ScoreBrush = Format.ScoreBrush(score),
                    Edges = edges.OrderByDescending(x => x.Thickness).Take(6).ToList(),
                });
            }
        }

        ConnectionsList.ItemsSource = rows.OrderByDescending(r => r.When).Take(500).ToList();
        GraphList.ItemsSource = graph.Take(12).ToList();
    }

    private void Row_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is Guid id)
            App.Window?.OpenDossier(id);
    }
}
