using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Radar.App.Services;
using Radar.Core.Filtering;
using Radar.Core.Model;
using Radar.Core.Reporting;

namespace Radar.App.Pages;

public sealed class SignalRow
{
    public string Weight { get; init; } = string.Empty;
    public Brush WeightBrush { get; init; } = null!;
    public string Title { get; init; } = string.Empty;
    public string Explanation { get; init; } = string.Empty;
    public string Evidence { get; init; } = string.Empty;
}

public sealed class ReplayRow
{
    public string When { get; init; } = string.Empty;
    public string Text { get; init; } = string.Empty;
}

public sealed class KeyValueRow
{
    public string Key { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
}

/// <summary>
/// Ficha de processo / dossiê: cabeçalho com identidade e score decomposto, abas de
/// replay, rede, arquivos, origem/cadeia, persistências, histórico e
/// anotações, mais as ações do usuário.
/// </summary>
public sealed partial class DossierPage : Page
{
    private ProcessExecution? _execution;

    public DossierPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is Guid id) LoadData(id);
    }

    private void LoadData(Guid executionId)
    {
        var store = AppServices.Store;
        _execution = store.GetExecution(executionId);
        if (_execution is null) return;
        var exec = _execution;

        ProcName.Text = exec.Binary.FileName;
        ProcPath.Text = exec.Binary.Path;
        var motw = exec.Binary.Motw is { FromInternet: true } m
            ? $" · MOTW: came from the internet{(m.HostUrl is { } u ? $" ({u})" : string.Empty)}"
            : string.Empty;
        ProcMeta.Text =
            $"PID {exec.Pid} · created {Format.LocalLong(exec.CreatedUtc)} · " +
            (exec.IsAlive ? "still running" : $"ended {Format.LocalLong(exec.ExitedUtc)} ({Format.Duration(exec.Duration)})") +
            $"\nSHA-256: {exec.Binary.Sha256 ?? "not computed"} · {Format.Bytes(exec.Binary.SizeBytes)}" +
            $"\nUser: {exec.Security.UserName ?? "?"} · integrity {exec.Security.IntegrityLevel}" +
            (exec.Security.Elevated ? " · ELEVATED" : string.Empty) +
            $" · {exec.PriorRunCountSameBinary} prior executions of this binary{motw}" +
            (exec.CommandLine is { } cl ? $"\nCommand line: {cl}" : string.Empty);

        SignatureText.Text = InvestigationReport.DescribeSignature(exec.Binary.Signature);
        SignatureText.Foreground = Format.SignatureBrush(exec.Binary.Signature.Status);
        OriginText.Text = exec.Origin is { } origin ? origin.Description : string.Empty;

        var score = exec.Score ?? Core.Analysis.SuspicionScore.Empty;
        ScoreNumber.Text = score.Total.ToString();
        ScoreBadge.Background = Format.BandBrush(score.Band);
        ScoreBand.Text = Format.BandName(score.Band);
        ScoreMuted.Text = score.Muted ? I18n.T("silenciado (marcado confiável)") : string.Empty;

        if (exec.Verdict != UserVerdict.None)
        {
            VerdictBadge.Visibility = Visibility.Visible;
            VerdictText.Text = exec.Verdict switch
            {
                UserVerdict.Trusted => I18n.T("marcado confiável"),
                UserVerdict.Suspicious => I18n.T("marcado suspeito"),
                _ => I18n.T("investigando"),
            };
        }

        TrustButton.Content = I18n.T("Marcar confiável");
        SuspectButton.Content = I18n.T("Marcar suspeito");
        InvestigateButton.Content = I18n.T("Investigando");
        OpenLocationButton.Content = I18n.T("Abrir local do arquivo");
        KillButton.Content = I18n.T("Encerrar processo");
        KillButton.Visibility = exec.IsAlive ? Visibility.Visible : Visibility.Collapsed;
        CopyIocItem.Text = I18n.T("Copiar indicadores");
        ReputationItem.Text = I18n.T("Pesquisar reputação") + " " + I18n.T("(abre no navegador, só o hash)");
        RemovalPlanItem.Text = I18n.T("Plano de remoção");
        ExportHtmlItem.Text = I18n.T("Exportar relatório") + " (HTML)";
        ExportJsonItem.Text = I18n.T("Exportar relatório") + " (JSON)";

        var signalRows = score.Signals.Select(s => new SignalRow
        {
            Weight = $"+{s.Weight}",
            WeightBrush = new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xC5, 0x0F, 0x1F)),
            Title = s.Title,
            Explanation = s.Explanation,
            Evidence = s.Evidence.Count > 0 ? I18n.T("Evidência: ") + string.Join("; ", s.Evidence) : string.Empty,
        }).Concat(score.Reducers.Select(r => new SignalRow
        {
            Weight = r.Weight.ToString(),
            WeightBrush = new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x10, 0x7C, 0x10)),
            Title = r.Title,
            Explanation = r.Explanation,
        })).ToList();
        SignalsList.ItemsSource = signalRows;
        NoSignals.Visibility = signalRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var replay = new List<(DateTimeOffset At, string Text)>
        {
            (exec.CreatedUtc, $"created by {Path.GetFileName(exec.CreatorImage ?? "?")} (PID {exec.CreatorPid})"),
        };
        foreach (var dns in store.GetDnsQueries(exec.ExecutionId))
            replay.Add((dns.TimestampUtc, $"resolved domain {dns.Domain}" +
                (dns.ResolvedAddresses.Count > 0 ? $" -> {string.Join(", ", dns.ResolvedAddresses.Take(3))}" : string.Empty)));
        foreach (var conn in store.GetConnections(exec.ExecutionId))
            replay.Add((conn.FirstSeenUtc,
                $"connected to {conn.ResolvedFromDomain ?? conn.RemoteAddress}:{conn.RemotePort} " +
                $"(up {Format.Bytes(conn.BytesSent)} / down {Format.Bytes(conn.BytesReceived)})" +
                (conn.ResolvedFromDomain is null ? " - direct IP, no DNS" : string.Empty)));
        foreach (var file in store.GetFileActivities(exec.ExecutionId))
            replay.Add((file.TimestampUtc, file.Kind switch
            {
                FileEventKind.SensitiveRead => $"read sensitive directory: {file.SensitiveCategory} ({file.Path})",
                FileEventKind.ExecutableDrop => $"created executable {file.Path}" +
                    (file.Sha256 is { } sha ? $" (SHA-256 {sha[..Math.Min(12, sha.Length)]}…)" : string.Empty),
                FileEventKind.SelfDelete => "the binary itself disappeared from disk (self-deletion)",
                FileEventKind.ArchiveStaging => $"compressed sensitive material into {file.Path}",
                _ => $"wrote {file.Path}",
            }));
        foreach (var module in store.GetModuleLoads(exec.ExecutionId))
            replay.Add((module.TimestampUtc,
                $"loaded module {module.ModulePath} ({Format.SignatureName(module.SignatureStatus)})"));
        if (exec.ExitedUtc is { } exited)
            replay.Add((exited, $"ended (exit code {exec.ExitCode?.ToString() ?? "?"})"));

        ReplayList.ItemsSource = replay.OrderBy(r => r.At)
            .Select(r => new ReplayRow { When = r.At.ToLocalTime().ToString("HH:mm:ss.fff"), Text = r.Text })
            .ToList();

        NetList.ItemsSource = store.GetConnections(exec.ExecutionId).Select(c => new KeyValueRow
        {
            Key = $"{c.ResolvedFromDomain ?? "direct IP"} - {c.RemoteAddress}:{c.RemotePort}/{c.Protocol}",
            Value = $"up {Format.Bytes(c.BytesSent)} / down {Format.Bytes(c.BytesReceived)} · {Format.Local(c.FirstSeenUtc)}",
        }).ToList();

        FilesList.ItemsSource = store.GetFileActivities(exec.ExecutionId).Select(f => new KeyValueRow
        {
            Key = f.Path,
            Value = $"{f.Kind}{(f.SensitiveCategory is { } cat ? $" · {cat}" : string.Empty)} · {Format.Local(f.TimestampUtc)}",
        }).ToList();

        ChainOrigin.Text = exec.Origin?.Description ?? "Origin not determined.";
        ChainList.ItemsSource = exec.Ancestry.Select((link, i) => new KeyValueRow
        {
            Key = new string(' ', i * 2) + "↳ " + (Path.GetFileName(link.ImagePath ?? string.Empty) is { Length: > 0 } n ? n : "?"),
            Value = $"PID {link.Pid}" + (link.StartedUtc is { } s ? $" · started {Format.Local(s)}" : string.Empty),
        }).ToList();

        var related = FindRelatedPersistence(exec);
        PersistList.ItemsSource = related.Select(p => new KeyValueRow
        {
            Key = $"{p.Name} ({p.Kind})" + (p.RemovedUtc is null ? string.Empty : " - removed"),
            Value = $"{p.Location} -> {p.Target} · seen on {Format.Local(p.FirstSeenUtc)}",
        }).ToList();

        if (exec.Binary.Sha256 is { } hash)
        {
            HistoryList.ItemsSource = store.GetExecutionsForBinary(hash, 50)
                .Where(x => x.ExecutionId != exec.ExecutionId)
                .Select(x => new SearchRow
                {
                    ExecutionId = x.ExecutionId,
                    Score = (x.Score?.Muted == true ? 0 : x.Score?.Total ?? 0).ToString(),
                    ScoreBrush = Format.ScoreBrush(x.Score?.Muted == true ? 0 : x.Score?.Total ?? 0),
                    Detail = $"PID {x.Pid} · {Format.Duration(x.Duration)} · {x.Security.UserName ?? "?"}",
                    When = Format.Local(x.CreatedUtc),
                }).ToList();
        }

        NotesBox.Text = exec.UserNotes ?? string.Empty;
    }

    private List<PersistenceEntry> FindRelatedPersistence(ProcessExecution exec)
    {
        var store = AppServices.Store;
        var result = store.GetPersistenceForTarget(exec.Binary.Path).ToList();
        foreach (var file in store.GetFileActivities(exec.ExecutionId)
                     .Where(f => f.Kind == FileEventKind.ExecutableDrop))
        {
            result.AddRange(store.GetPersistenceForTarget(file.Path));
        }
        result.AddRange(store.GetPersistenceEntries(includeRemoved: true)
            .Where(p => p.InstallerExecutionId == exec.ExecutionId));
        return result.DistinctBy(p => p.Id).ToList();
    }

    private void SetVerdict(UserVerdict verdict)
    {
        if (_execution is null) return;
        AppServices.Store.SetVerdict(_execution.ExecutionId, verdict, NotesBox.Text);

        // Confiança amarrada a hash+caminho+emissor, nunca só nome
        if (verdict == UserVerdict.Trusted && _execution.Binary.Sha256 is { } hash)
        {
            AppServices.Store.AddTrustListEntry(new TrustListEntry
            {
                Sha256 = hash,
                Path = _execution.Binary.Path,
                SignerSubject = _execution.Binary.Signature.Subject,
                AddedUtc = DateTimeOffset.UtcNow,
                Note = "marcado pela ficha do processo",
            });
        }
        LoadData(_execution.ExecutionId);
    }

    private void Trust_Click(object sender, RoutedEventArgs e) => SetVerdict(UserVerdict.Trusted);
    private void Suspect_Click(object sender, RoutedEventArgs e) => SetVerdict(UserVerdict.Suspicious);
    private void Investigate_Click(object sender, RoutedEventArgs e) => SetVerdict(UserVerdict.Investigating);

    private void Kill_Click(object sender, RoutedEventArgs e)
    {
        if (_execution is null) return;
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(_execution.Pid);
            proc.Kill();
        }
        catch { }
        LoadData(_execution.ExecutionId);
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (_execution is null) return;
        try
        {
            System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{_execution.Binary.Path}\"");
        }
        catch { }
    }

    private InvestigationReport BuildReport()
    {
        var exec = _execution!;
        var store = AppServices.Store;
        return new InvestigationReport
        {
            Execution = exec,
            Connections = store.GetConnections(exec.ExecutionId),
            DnsQueries = store.GetDnsQueries(exec.ExecutionId),
            FileActivities = store.GetFileActivities(exec.ExecutionId),
            RelatedPersistence = FindRelatedPersistence(exec),
            RelatedExecutions = store.GetChildren(exec.ExecutionId),
            GeneratedUtc = DateTimeOffset.UtcNow,
        };
    }

    private void CopyIoc_Click(object sender, RoutedEventArgs e)
    {
        if (_execution is null) return;
        var package = new global::Windows.ApplicationModel.DataTransfer.DataPackage();
        package.SetText(BuildReport().FormatIndicators());
        global::Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
    }

    private void Reputation_Click(object sender, RoutedEventArgs e)
    {
        // Abre no navegador, sem enviar o arquivo. Só o hash.
        if (_execution?.Binary.Sha256 is not { } hash) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = $"https://www.virustotal.com/gui/file/{hash.ToLowerInvariant()}",
                UseShellExecute = true,
            });
        }
        catch { }
    }

    private async void RemovalPlan_Click(object sender, RoutedEventArgs e)
    {
        if (_execution is null) return;
        var exec = _execution;
        var store = AppServices.Store;
        var siblings = exec.ParentExecutionId is { } parent
            ? store.GetChildren(parent)
            : store.GetChildren(exec.ExecutionId);

        var items = RemovalPlanBuilder.Build(exec, FindRelatedPersistence(exec),
            store.GetFileActivities(exec.ExecutionId), siblings);

        var panel = new StackPanel { Spacing = 10, MaxWidth = 560 };
        panel.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.7,
            Text = I18n.T("Checklist com tudo que o Radar sabe. A execução das remoções fica com você (ou com seu antivírus, após denúncia)."),
        });
        foreach (var item in items)
        {
            var sp = new StackPanel { Spacing = 2 };
            sp.Children.Add(new CheckBox { Content = item.Title });
            sp.Children.Add(new TextBlock
            {
                Text = item.Detail,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Opacity = 0.65,
                Margin = new Thickness(28, 0, 0, 0),
            });
            panel.Children.Add(sp);
        }

        await new ContentDialog
        {
            Title = string.Format(I18n.T("Plano de remoção assistida: {0}"), exec.Binary.FileName),
            Content = new ScrollViewer { Content = panel, MaxHeight = 480 },
            CloseButtonText = I18n.T("Fechar"),
            XamlRoot = XamlRoot,
        }.ShowAsync();
    }

    private async void ExportHtml_Click(object sender, RoutedEventArgs e) => await Export("html");
    private async void ExportJson_Click(object sender, RoutedEventArgs e) => await Export("json");

    private async Task Export(string format)
    {
        if (_execution is null) return;
        var report = BuildReport();
        var dir = AppServices.Settings.ReportsDirectory;
        Directory.CreateDirectory(dir);
        var name = $"radar-{_execution.Binary.FileName}-{DateTime.Now:yyyyMMdd-HHmmss}.{format}";
        var path = Path.Combine(dir, name);
        await File.WriteAllTextAsync(path, format == "html" ? report.ToHtml() : report.ToJson());
        try
        {
            System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
        }
        catch { }
    }

    private void SaveNotes_Click(object sender, RoutedEventArgs e)
    {
        if (_execution is null) return;
        AppServices.Store.SetVerdict(_execution.ExecutionId, _execution.Verdict, NotesBox.Text);
    }

    private void History_Clicked(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is SearchRow row) LoadData(row.ExecutionId);
    }
}
