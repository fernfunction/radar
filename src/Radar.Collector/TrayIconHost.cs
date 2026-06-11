using System.Drawing;
using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Collector;

/// <summary>
/// Ícone na bandeja do Windows, obrigatório quando a coleta roda independente da UI: nada de
/// processo invisível ao usuário. Menu: abrir o Radar, status resumido, pausar,
/// encerrar. Reflete o estado (normal/pausado/erro) e exibe selo de achados Críticos.
/// </summary>
public sealed class TrayIconHost : IDisposable
{
    private readonly CollectorContext _ctx;
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _statusItem;
    private readonly ToolStripMenuItem _pauseItem;
    private readonly System.Windows.Forms.Timer _refreshTimer;
    private readonly Icon _normalIcon;
    private readonly Icon _pausedIcon;
    private readonly Icon _errorIcon;
    private readonly Icon _criticalIcon;
    private Guid? _lastCriticalExecution;

    public event Action? ExitRequested;

    public TrayIconHost(CollectorContext ctx)
    {
        _ctx = ctx;
        // Mesma arte do ícone do programa (RadarArt), recolorida por estado.
        _normalIcon = RadarArt.CreateIcon(32, RadarArt.Normal);
        _pausedIcon = RadarArt.CreateIcon(32, RadarArt.Paused);
        _errorIcon = RadarArt.CreateIcon(32, RadarArt.Error);
        _criticalIcon = RadarArt.CreateIcon(32, RadarArt.Critical);

        var menu = new ContextMenuStrip();
        _statusItem = new ToolStripMenuItem("Status…") { Enabled = false };
        _pauseItem = new ToolStripMenuItem("Pause collection", null, (_, _) => TogglePause());
        menu.Items.Add(new ToolStripMenuItem("Open Radar", null, (_, _) => OpenUi()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_statusItem);
        menu.Items.Add(_pauseItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Stop background collection", null, (_, _) => ExitRequested?.Invoke()));

        _icon = new NotifyIcon
        {
            Icon = _normalIcon,
            Text = "Radar - collection active",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => OpenUi();
        _icon.BalloonTipClicked += (_, _) => OpenUi(_lastCriticalExecution);

        _refreshTimer = new System.Windows.Forms.Timer { Interval = 3000 };
        _refreshTimer.Tick += (_, _) => Refresh();
        _refreshTimer.Start();
    }

    /// <summary>Toast de achado Crítico com ação "abrir dossiê", com antifadiga.</summary>
    private readonly Queue<DateTimeOffset> _notificationTimestamps = new();

    public void NotifyFinding(ProcessExecution execution)
    {
        if (!_ctx.Settings.Notifications.ToastEnabled) return;
        lock (_notificationTimestamps)
        {
            var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
            while (_notificationTimestamps.Count > 0 && _notificationTimestamps.Peek() < cutoff)
                _notificationTimestamps.Dequeue();
            if (_notificationTimestamps.Count >= _ctx.Settings.Rates.MaxNotificationsPerHour) return;
            _notificationTimestamps.Enqueue(DateTimeOffset.UtcNow);
        }

        _lastCriticalExecution = execution.ExecutionId;
        var score = execution.Score?.Total ?? 0;
        var topSignal = execution.Score?.Signals.OrderByDescending(s => s.Weight).FirstOrDefault();
        _icon.ShowBalloonTip(10_000,
            $"Radar - {Core.Reporting.InvestigationReport.BandPt(SuspicionScore.BandFor(score))} ({score})",
            $"{execution.Binary.FileName}: {topSignal?.Title ?? "noteworthy activity"}. Click to open the dossier.",
            ToolTipIcon.Warning);
    }

    private void TogglePause()
    {
        _ctx.Paused = !_ctx.Paused;
        _ctx.Log.Information(_ctx.Paused ? "Collection paused from the tray" : "Collection resumed from the tray");
        if (_ctx.Paused)
            _ctx.Store.AddSystemMarker(new SystemMarker
            { TimestampUtc = DateTimeOffset.UtcNow, Kind = SystemMarkerKind.CollectorPaused });
        Refresh();
    }

    private void OpenUi(Guid? executionId = null)
    {
        try
        {
            var uiPath = Path.Combine(AppContext.BaseDirectory, "Radar.App.exe");
            if (!File.Exists(uiPath))
            {
                // layout de desenvolvimento: procura o vizinho compilado
                var dev = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
                    @"..\..\..\..\Radar.App\bin\x64\Debug\net10.0-windows10.0.19041.0\win-x64\Radar.App.exe"));
                if (File.Exists(dev)) uiPath = dev;
            }
            var args = executionId is { } id ? $"--execution {id:N}" : string.Empty;
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = uiPath,
                Arguments = args,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            _ctx.Log.Warning(ex, "Could not open the UI");
            _icon.ShowBalloonTip(5000, "Radar", "Could not open the interface (Radar.App.exe not found).",
                ToolTipIcon.Error);
        }
    }

    private void Refresh()
    {
        var modulesOn = Enum.GetValues<CollectionModule>().Count(m => _ctx.Settings.IsModuleEnabled(m));
        var status = _ctx.Paused ? "paused" : _ctx.LastError is not null ? "with warnings" : "active";
        _statusItem.Text = $"Collection {status} - {_ctx.EventsPerMinute:0}/min, {modulesOn} modules" +
                           (_ctx.Elevated ? string.Empty : " (NO ELEVATION)");
        _pauseItem.Text = _ctx.Paused ? "Resume collection" : "Pause collection temporarily";

        var (icon, text) = (_ctx.Paused, _ctx.CriticalUnseen > 0, _ctx.LastError) switch
        {
            (true, _, _) => (_pausedIcon, "Radar - collection paused"),
            (_, true, _) => (_criticalIcon, $"Radar - {_ctx.CriticalUnseen} unseen critical finding(s)"),
            (_, _, not null) => (_errorIcon, "Radar - degraded collection"),
            _ => (_normalIcon, "Radar - collection active"),
        };
        _icon.Icon = icon;
        _icon.Text = text.Length > 63 ? text[..63] : text;
    }

    public void Dispose()
    {
        _refreshTimer.Dispose();
        _icon.Visible = false;
        _icon.Dispose();
        _normalIcon.Dispose();
        _pausedIcon.Dispose();
        _errorIcon.Dispose();
        _criticalIcon.Dispose();
    }
}
