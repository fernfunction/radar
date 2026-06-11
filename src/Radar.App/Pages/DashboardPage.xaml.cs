using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Radar.App.Services;
using Radar.Core.Abstractions;
using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.App.Pages;

public sealed class FindingCard
{
    public Guid ExecutionId { get; init; }
    public string Text { get; init; } = string.Empty;
    public Brush BandBrush { get; init; } = null!;
}

public sealed class TopRow
{
    public Guid ExecutionId { get; init; }
    public int Score { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public string When { get; init; } = string.Empty;
    public Brush BandBrush { get; init; } = null!;
}

/// <summary>Dashboard: resumo 24h/7d, achados em linguagem natural, top por score, saúde.</summary>
public sealed partial class DashboardPage : Page
{
    public DashboardPage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void LoadData()
    {
        TitleText.Text = I18n.T("Painel");
        FindingsTitle.Text = I18n.T("Achados recentes");
        TopTitle.Text = I18n.T("Top por score") + " · " + I18n.T("Últimos 7 dias");
        HealthTitle.Text = I18n.T("Saúde da coleta");
        ChartTitle.Text = I18n.T("Atividade por dia (7d)");

        var now = DateTimeOffset.UtcNow;
        var store = AppServices.Store;
        var settings = AppServices.Settings;
        var threshold = TimeSpan.FromSeconds(settings.ShortLivedThresholdSeconds);

        var last7d = store.QueryExecutions(new ExecutionQuery { FromUtc = now.AddDays(-7), Limit = 5000 });
        var last24h = last7d.Where(e => e.CreatedUtc >= now.AddHours(-24)).ToList();

        CardNewProcs.Text = last24h.Count.ToString();
        CardNewProcsLabel.Text = I18n.T("Processos novos") + " (24h)";

        var shortLivedNoteworthy = last24h.Count(e =>
            e.IsShortLived(threshold) && (e.Score?.Total ?? 0) >= 25 && e.Score?.Muted != true);
        CardShortLived.Text = shortLivedNoteworthy.ToString();
        CardShortLivedLabel.Text = I18n.T("Vida curta") + " " + I18n.T("dignos de nota (24h)");

        var persistence = store.GetPersistenceEntries(includeRemoved: true)
            .Count(p => p.FirstSeenUtc >= now.AddHours(-24));
        CardPersistence.Text = persistence.ToString();
        CardPersistenceLabel.Text = I18n.T("Persistências adicionadas") + " (24h)";

        long uploadUntrusted = 0;
        foreach (var exec in last24h.Where(e =>
                     e.Binary.Signature.Status is not SignatureStatus.SignedTrusted))
        {
            uploadUntrusted += store.GetConnections(exec.ExecutionId).Sum(c => c.BytesSent);
        }
        CardUpload.Text = Format.Bytes(uploadUntrusted);
        CardUploadLabel.Text = I18n.T("Upload por processos não confiáveis (24h)");

        var findings = last7d
            .Where(e => (e.Score?.Total ?? 0) >= 25 && e.Score?.Muted != true)
            .OrderByDescending(e => e.Score!.Total)
            .ThenByDescending(e => e.CreatedUtc)
            .Take(6)
            .Select(e => new FindingCard
            {
                ExecutionId = e.ExecutionId,
                Text = ComposeFinding(e),
                BandBrush = Format.BandBrush(e.Score!.Band),
            })
            .ToList();
        FindingsList.ItemsSource = findings;
        NoFindings.Visibility = findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        NoFindings.Text = I18n.T("Nada digno de nota no período. É assim que uma máquina saudável deve aparecer.");

        TopList.ItemsSource = last7d
            .Where(e => e.Score is { Muted: false, Total: > 0 })
            .OrderByDescending(e => e.Score!.Total)
            .Take(5)
            .Select(e => new TopRow
            {
                ExecutionId = e.ExecutionId,
                Score = e.Score!.Total,
                Name = e.Binary.FileName,
                Detail = e.Binary.Path,
                When = Format.Local(e.CreatedUtc),
                BandBrush = Format.BandBrush(e.Score.Band),
            })
            .ToList();

        var health = AppServices.ReadHealth();
        var running = health is { Running: true } && health.IsFresh;
        HealthStatus.Text = running
            ? health!.Paused ? "⏸ " + I18n.T("Coleta pausada") : "● " + I18n.T("Coleta ativa")
            : "○ " + I18n.T("Coleta parada");
        if (running)
        {
            HealthDetail.Text = string.Format(
                I18n.T("{0:0} eventos/min · banco {1} · {2} execuções · RAM do coletor {3}"),
                health!.EventsPerMinute, Format.Bytes(health.DatabaseBytes),
                health.ExecutionCount, Format.Bytes(health.WorkingSetBytes)) +
                (health.Elevated ? string.Empty : "\n" + I18n.T("⚠ SEM ELEVAÇÃO: coleta degradada (sem ETW de kernel).")) +
                (health.LastError is { } err ? $"\n⚠ {err}" : string.Empty);
            HealthModules.Text = I18n.T("Módulos: ") + string.Join(", ",
                health.Modules.Where(m => m.Value).Select(m => m.Key));
            StartCollectorButton.Visibility = Visibility.Collapsed;
        }
        else
        {
            HealthDetail.Text = I18n.T("Sem coletor, processos de vida curta que rodarem agora ficarão invisíveis para sempre.");
            HealthModules.Text = string.Empty;
            StartCollectorButton.Content = I18n.T("Iniciar coleta");
            StartCollectorButton.Visibility = Visibility.Visible;
        }

        var byDay = Enumerable.Range(0, 7)
            .Select(i => now.AddDays(-6 + i).ToLocalTime().Date)
            .Select(day => (Day: day, Count: last7d.Count(e => e.CreatedUtc.ToLocalTime().Date == day)))
            .ToList();
        ActivityChart.SetData(
            byDay.Select(d => (double)d.Count).ToList(),
            byDay.Select(d => d.Day.ToString("dd/MM")).ToList());
    }

    /// <summary>Monta a narração textual de um achado (em inglês, como as demais saídas de análise).</summary>
    private static string ComposeFinding(ProcessExecution e)
    {
        var when = e.CreatedUtc.ToLocalTime();
        var dayWord = when.Date == DateTime.Today ? "Today" :
            when.Date == DateTime.Today.AddDays(-1) ? "Yesterday" : when.ToString("dd/MM");
        var parts = new List<string>();

        var signature = e.Binary.Signature.Status switch
        {
            SignatureStatus.Unsigned => "unsigned binary",
            SignatureStatus.SignedInvalid => "binary with an invalid signature",
            SignatureStatus.SignedRevoked => "binary with a revoked certificate",
            SignatureStatus.SelfSigned => "self-signed binary",
            _ => e.Binary.FileName,
        };
        var location = Core.Filtering.VisibilityFilter.IsUserWritableDirectory(e.Binary.Path)
            ? " in a writable directory" : string.Empty;
        parts.Add($"{signature}{location} ({e.Binary.FileName})");

        if (e.Duration is { } d && d.TotalSeconds <= 30) parts.Add($"ran for {Format.Duration(d)}");

        var signals = e.Score?.Signals ?? [];
        foreach (var signal in signals.Where(s => s.Kind is SignalKind.CredentialDirectoryRead
                     or SignalKind.ShortLivedWithUpload or SignalKind.Masquerading or SignalKind.SelfDeletion
                     or SignalKind.DropAndExecute or SignalKind.PersistenceOnFirstRun).Take(2))
        {
            parts.Add(signal.Title.ToLowerInvariant());
        }

        return $"{dayWord} {when:HH:mm} - {string.Join(", ", parts)}. Score {e.Score?.Total ?? 0}.";
    }

    private void Finding_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is Guid id)
            App.Window?.OpenDossier(id);
    }

    private void StartCollector_Click(object sender, RoutedEventArgs e)
    {
        AppServices.StartCollector();
        DispatcherQueue.TryEnqueue(async () =>
        {
            await Task.Delay(2000);
            LoadData();
        });
    }
}
