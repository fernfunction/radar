using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Radar.App.Services;
using Radar.Core.Abstractions;
using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.App.Pages;

public sealed class ShortLivedGroupRow
{
    public string Name { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public int MaxScore { get; init; }
    public Brush BandBrush { get; init; } = null!;
    public string Stats { get; init; } = string.Empty;
    public string LastSeen { get; init; } = string.Empty;
    public string RegularityWarning { get; init; } = string.Empty;
    public List<ShortLivedExecRow> Executions { get; init; } = [];
}

public sealed class ShortLivedExecRow
{
    public Guid ExecutionId { get; init; }
    public string When { get; init; } = string.Empty;
    public string Duration { get; init; } = string.Empty;
    public Brush DurationBrush { get; init; } = null!;
    public string CommandLine { get; init; } = string.Empty;
    public string Score { get; init; } = string.Empty;
}

/// <summary>
/// Vista Short-Lived: agrupamento por binário com estatísticas
/// de frequência/regularidade, supressão auditável e acesso ao replay pelo dossiê.
/// </summary>
public sealed partial class ShortLivedPage : Page
{
    public ShortLivedPage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void Filters_Changed(object sender, object e) => LoadData();

    private void LoadData()
    {
        if (GroupsList is null) return;
        TitleText.Text = I18n.T("Vida curta");

        var settings = AppServices.Settings;
        var threshold = TimeSpan.FromSeconds(settings.ShortLivedThresholdSeconds);
        var days = PeriodCombo.SelectedIndex switch { 0 => 1, 2 => 30, _ => 7 };

        var executions = AppServices.Store.QueryExecutions(new ExecutionQuery
        {
            FromUtc = DateTimeOffset.UtcNow.AddDays(-days),
            Limit = 10_000,
        });

        var uploads = new Dictionary<Guid, long>();
        foreach (var exec in executions.Where(x => x.IsShortLived(threshold)))
        {
            var sent = AppServices.Store.GetConnections(exec.ExecutionId).Sum(c => c.BytesSent);
            if (sent > 0) uploads[exec.ExecutionId] = sent;
        }

        var view = AppServices.ShortLived.Build(executions, threshold, uploads,
            includeSuppressed: ShowSuppressed.IsOn);

        var groups = view.Groups.AsEnumerable();
        groups = SortCombo.SelectedIndex switch
        {
            1 => groups.OrderByDescending(g => g.LastUtc),
            2 => groups.OrderByDescending(g => g.TotalUploadBytes),
            3 => groups.OrderByDescending(g => g.Count),
            _ => groups, // já vem por score
        };

        GroupsList.ItemsSource = groups.Select(g => new ShortLivedGroupRow
        {
            Name = g.DisplayName + (g.Suppressed ? "  (suppressed)" : string.Empty),
            Path = g.ImagePath,
            MaxScore = g.MaxScore,
            BandBrush = Format.ScoreBrush(g.MaxScore),
            Stats = $"{g.Count}x · {g.CommandLineVariants} command-line variants" +
                    (g.TotalUploadBytes > 0 ? $" · up {Format.Bytes(g.TotalUploadBytes)}" : string.Empty) +
                    (g.MeanInterval is { } mi ? $" · mean interval {Format.Duration(mi)}" : string.Empty),
            LastSeen = Format.Local(g.LastUtc),
            RegularityWarning = g.SuspiciouslyRegular
                ? "⚠ extreme regularity (hidden task? beacon?)" : string.Empty,
            Executions = g.Executions.OrderByDescending(x => x.CreatedUtc).Take(50).Select(x =>
            {
                var band = x.ShortLivedBand(threshold);
                return new ShortLivedExecRow
                {
                    ExecutionId = x.ExecutionId,
                    When = Format.Local(x.CreatedUtc),
                    Duration = Format.Duration(x.Duration),
                    DurationBrush = band switch
                    {
                        ShortLivedBand.SubSecond => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xC5, 0x0F, 0x1F)),
                        ShortLivedBand.OneToFive => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xCA, 0x50, 0x10)),
                        _ => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x98, 0x6F, 0x0B)),
                    },
                    CommandLine = x.CommandLine ?? string.Empty,
                    Score = (x.Score?.Muted == true ? 0 : x.Score?.Total ?? 0).ToString(),
                };
            }).ToList(),
        }).ToList();

        CountBadge.Value = view.Groups.Count;
        // Contador visível de supressão para manter auditabilidade
        SuppressedText.Text = view.SuppressedExecutionCount > 0
            ? $"{view.SuppressedExecutionCount} {I18n.T("execuções suprimidas")} " +
              string.Format(I18n.T("({0} binários efêmeros legítimos)"), view.SuppressedGroupCount)
            : string.Empty;
    }

    private void Execution_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is Guid id)
            App.Window?.OpenDossier(id);
    }
}
