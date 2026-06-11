using System.Diagnostics;
using Microsoft.Win32;
using Radar.Collector;
using Radar.Core.Configuration;
using Radar.Core.Model;
using Radar.Data;
using Radar.Windows;
using Serilog;
using Serilog.Events;

// Auto-elevação opcional: sessões ETW de kernel exigem elevação. O manifest é asInvoker, assim o
// depurador do VS Code consegue iniciar o processo sem o erro ERROR_ELEVATION_REQUIRED, e a
// elevação acontece sob demanda, via --elevate (usado pela config de debug e pelo botão
// "Iniciar coleta" da UI). Se o usuário cancelar o UAC, seguimos em modo degradado. Esta
// verificação vem ANTES do mutex para a instância elevada assumir sem disputa.
var cliArgs = Environment.GetCommandLineArgs();
if (cliArgs.Any(a => a.Equals("--elevate", StringComparison.OrdinalIgnoreCase)) &&
    !ProcessInspector.IsCurrentProcessElevated())
{
    try
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = Environment.ProcessPath!,
            UseShellExecute = true,
            Verb = "runas", // dispara o UAC
            Arguments = string.Join(' ', cliArgs.Skip(1)
                .Where(a => !a.Equals("--elevate", StringComparison.OrdinalIgnoreCase))),
        });
        return; // a instância elevada assume; esta sai sem segurar o mutex
    }
    catch (System.ComponentModel.Win32Exception)
    {
        // UAC cancelado ou negado: continua em modo degradado
    }
}

using var mutex = new Mutex(initiallyOwned: true, "Local\\RadarCollectorSingleton", out var isNew);
if (!isNew)
{
    MessageBox.Show("The Radar collector is already running (see the tray icon).",
        "Radar", MessageBoxButtons.OK, MessageBoxIcon.Information);
    return;
}

var dataRoot = DataRootManager.ResolveDataRoot();
Directory.CreateDirectory(dataRoot);
var settings = RadarSettings.LoadOrDefault(Path.Combine(dataRoot, "settings.json"));
settings.DataRoot = dataRoot;
if (!File.Exists(settings.SettingsPath)) settings.Save();
DataRootManager.ApplyRestrictiveAcls(dataRoot); // o banco de evidências é alvo

// Logs operacionais NÃO sensíveis: nada de linha de comando, domínio ou hash de usuário
Directory.CreateDirectory(settings.LogsDirectory);
var logLevel = settings.LogLevel.ToLowerInvariant() switch
{
    "error" => LogEventLevel.Error,
    "warning" or "aviso" => LogEventLevel.Warning,
    "diagnostic" or "debug" or "diagnóstico" => LogEventLevel.Debug,
    _ => LogEventLevel.Information,
};
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Is(logLevel)
    .WriteTo.File(
        Path.Combine(settings.LogsDirectory, "collector-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        fileSizeLimitBytes: 16 * 1024 * 1024,
        rollOnFileSizeLimit: true)
    .CreateLogger();

Log.Information("Radar Collector 0.1.0 starting. Data root {Root}", dataRoot);

ApplicationConfiguration.Initialize();

var ctx = new CollectorContext(settings, Log.Logger);
var pipeline = new EnrichmentPipeline(ctx);
var etw = new EtwCollector(ctx, pipeline);
var routines = new PeriodicRoutines(ctx, pipeline, etw);
var health = new HealthChannel(ctx);
var tray = new TrayIconHost(ctx);

pipeline.CriticalFinding += execution => tray.NotifyFinding(execution);

void Shutdown()
{
    if (ctx.StopRequested) return;
    ctx.StopRequested = true;
    Log.Information("Stopping collection");
    try
    {
        ctx.Store.AddSystemMarker(new SystemMarker
        { TimestampUtc = DateTimeOffset.UtcNow, Kind = SystemMarkerKind.CollectorStopped });
        ctx.Store.SaveBaseline(ctx.BaselineState);
    }
    catch { }
    routines.Dispose();
    etw.Dispose();
    pipeline.Dispose();
    health.Dispose();
    tray.Dispose();
    ctx.Dispose();
    Log.CloseAndFlush();
    Application.Exit();
}

tray.ExitRequested += Shutdown;
health.StopCommanded += () =>
{
    // comando vindo da UI chega em thread de timer; volta para a thread da bandeja
    Application.OpenForms.Cast<Form>().FirstOrDefault()?.BeginInvoke(Shutdown);
    if (Application.OpenForms.Count == 0) Shutdown();
};
AppDomain.CurrentDomain.ProcessExit += (_, _) => Shutdown();

SystemEvents.PowerModeChanged += (_, e) =>
{
    if (e.Mode == PowerModes.Resume)
        ctx.Store.AddSystemMarker(new SystemMarker
        { TimestampUtc = DateTimeOffset.UtcNow, Kind = SystemMarkerKind.ResumeFromSleep });
};
SystemEvents.SessionSwitch += (_, e) =>
{
    var kind = e.Reason switch
    {
        SessionSwitchReason.SessionLogon or SessionSwitchReason.SessionUnlock => SystemMarkerKind.Logon,
        SessionSwitchReason.SessionLogoff or SessionSwitchReason.SessionLock => SystemMarkerKind.Logoff,
        _ => SystemMarkerKind.Unknown,
    };
    if (kind != SystemMarkerKind.Unknown)
        ctx.Store.AddSystemMarker(new SystemMarker
        { TimestampUtc = DateTimeOffset.UtcNow, Kind = kind, Detail = e.Reason.ToString() });
};
System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += (_, _) =>
{
    try
    {
        ctx.Store.AddSystemMarker(new SystemMarker
        { TimestampUtc = DateTimeOffset.UtcNow, Kind = SystemMarkerKind.NetworkChange });
    }
    catch { }
};

ctx.Store.AddSystemMarker(new SystemMarker
{
    TimestampUtc = DateTimeOffset.UtcNow,
    Kind = SystemMarkerKind.CollectorStarted,
    Detail = ctx.Elevated ? "full collection (elevated)" : "degraded collection (no elevation)",
});

etw.Start();
Log.Information("Collector ready. Elevated: {Elevated}. Active modules: {Modules}",
    ctx.Elevated,
    string.Join(", ", Enum.GetValues<CollectionModule>().Where(m => settings.IsModuleEnabled(m))));

// Loop de mensagens da bandeja: mantém o processo vivo
Application.Run();
