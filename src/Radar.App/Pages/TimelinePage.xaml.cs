using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Radar.App.Services;
using Radar.Core.Model;

namespace Radar.App.Pages;

public sealed class TimelineRow
{
    public Guid? ExecutionId { get; init; }
    public string When { get; init; } = string.Empty;
    public string Glyph { get; init; } = string.Empty;
    public Brush Brush { get; init; } = null!;
    public string Title { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public string Score { get; init; } = string.Empty;
    public Brush ScoreBrush { get; init; } = null!;
    public Visibility ScoreVisibility { get; init; }
}

/// <summary>
/// Timeline de Atividade: cronologia com densidade por hora, filtros combináveis e
/// marcadores de contexto do sistema (logon, suspensão, troca de rede).
/// </summary>
public sealed partial class TimelinePage : Page
{
    public TimelinePage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void Filters_Changed(object sender, object e) => LoadData();

    private void LoadData()
    {
        if (EventsList is null) return;
        TitleText.Text = I18n.T("Linha do tempo");

        var days = PeriodCombo.SelectedIndex switch { 1 => 7, 2 => 30, _ => 1 };
        var from = DateTimeOffset.UtcNow.AddDays(-days);
        var minScore = (int)MinScoreSlider.Value;

        var events = AppServices.Store.GetTimeline(from, DateTimeOffset.UtcNow, minScore);

        // Filtro por usuário exige resolver a execução
        var userFilter = UserFilter.Text?.Trim();
        var onlyNet = OnlyNetworked.IsChecked == true;
        IEnumerable<TimelineEvent> filtered = events;
        if (!string.IsNullOrEmpty(userFilter) || onlyNet)
        {
            filtered = events.Where(evt =>
            {
                if (evt.ExecutionId is not { } id) return string.IsNullOrEmpty(userFilter) && !onlyNet;
                var exec = AppServices.Store.GetExecution(id);
                if (exec is null) return false;
                if (!string.IsNullOrEmpty(userFilter) &&
                    exec.Security.UserName?.Contains(userFilter, StringComparison.OrdinalIgnoreCase) != true)
                    return false;
                if (onlyNet && AppServices.Store.GetConnections(id).Count == 0) return false;
                return true;
            });
        }

        var rows = filtered.Take(1000).Select(evt => new TimelineRow
        {
            ExecutionId = evt.ExecutionId,
            When = Format.Local(evt.TimestampUtc),
            Glyph = Format.TimelineGlyph(evt.Kind),
            Brush = evt.Kind switch
            {
                TimelineEventKind.SensitiveRead or TimelineEventKind.SelfDelete =>
                    new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xC5, 0x0F, 0x1F)),
                TimelineEventKind.ExecutableDrop or TimelineEventKind.PersistenceInstalled =>
                    new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xCA, 0x50, 0x10)),
                TimelineEventKind.SystemMarker =>
                    new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x60, 0x7D, 0x8B)),
                _ => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x90, 0x90, 0x90)),
            },
            Title = evt.Title,
            Detail = evt.Detail ?? string.Empty,
            Score = evt.Score.ToString(),
            ScoreBrush = Format.ScoreBrush(evt.Score),
            ScoreVisibility = evt.Score > 0 ? Visibility.Visible : Visibility.Collapsed,
        }).ToList();
        EventsList.ItemsSource = rows;

        var buckets = days == 1 ? 24 : days;
        var counts = new int[buckets];
        var labels = new string[buckets];
        var nowLocal = DateTimeOffset.Now;
        foreach (var evt in events)
        {
            var local = evt.TimestampUtc.ToLocalTime();
            var index = days == 1
                ? 23 - (int)Math.Clamp((nowLocal - local).TotalHours, 0, 23)
                : buckets - 1 - (int)Math.Clamp((nowLocal.Date - local.Date).TotalDays, 0, buckets - 1);
            if (index is >= 0 && index < buckets) counts[index]++;
        }
        for (var i = 0; i < buckets; i++)
        {
            labels[i] = days == 1
                ? nowLocal.AddHours(-(23 - i)).ToString("HH'h'")
                : nowLocal.Date.AddDays(-(buckets - 1 - i)).ToString("dd/MM");
        }
        DensityChart.SetData(counts.Select(c => (double)c).ToList(), labels);
    }

    private void Event_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is Guid id)
            App.Window?.OpenDossier(id);
    }
}
