using Microsoft.UI.Xaml;
using Radar.Data;

namespace Radar.App;

public partial class App : Application
{
    public static MainWindow? Window { get; private set; }

    public App()
    {
        InitializeComponent();

        // WinUI 3 encerra o processo silenciosamente em exceção não tratada na thread de UI
        // (janela "abre e fecha"). Capturamos tudo num arquivo de crash para diagnóstico.
        UnhandledException += (_, e) =>
        {
            LogCrash("UI", e.Exception);
            e.Handled = true; // mantém o app vivo para o usuário ver o estado
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => LogCrash("AppDomain", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => { LogCrash("Task", e.Exception); e.SetObserved(); };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            Services.AppServices.Initialize(Environment.GetCommandLineArgs());
            Window = new MainWindow();
            Window.Activate();
        }
        catch (Exception ex)
        {
            LogCrash("OnLaunched", ex);
            throw;
        }
    }

    internal static void LogCrash(string source, Exception? ex)
    {
        try
        {
            var root = DataRootManager.ResolveDataRoot();
            var dir = Path.Combine(root, "logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "ui-crash.log"),
                $"{DateTimeOffset.Now:o} [{source}] {ex?.GetType().Name}: {ex?.Message}\n{ex}\n\n");
        }
        catch
        {
            // último recurso: não há onde registrar
        }
    }
}
