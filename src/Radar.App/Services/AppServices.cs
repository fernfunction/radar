using System.Text.Json;
using Radar.Core.Abstractions;
using Radar.Core.Analysis;
using Radar.Core.Catalog;
using Radar.Core.Configuration;
using Radar.Data;

namespace Radar.App.Services;

/// <summary>Saúde do coletor lida de health.json, escrita pelo processo do coletor.</summary>
public sealed record HealthSnapshot
{
    public bool Running { get; init; }
    public bool Paused { get; init; }
    public bool Elevated { get; init; }
    public Dictionary<string, bool> Modules { get; init; } = [];
    public double EventsPerMinute { get; init; }
    public long WorkingSetBytes { get; init; }
    public string? LastError { get; init; }
    public long DatabaseBytes { get; init; }
    public int ExecutionCount { get; init; }
    public int CriticalUnseen { get; init; }
    public DateTimeOffset UpdatedUtc { get; init; }

    public bool IsFresh => DateTimeOffset.UtcNow - UpdatedUtc < TimeSpan.FromSeconds(10);
}

/// <summary>
/// Composição da UI: configurações, banco (a UI lê o histórico e grava vereditos/lista de
/// confiança), analisadores do Core e controle do coletor em segundo plano.
/// </summary>
public static class AppServices
{
    public static RadarSettings Settings { get; private set; } = null!;
    public static SqliteEventStore Store { get; private set; } = null!;
    public static CuratedLists Lists { get; private set; } = null!;
    public static ShortLivedAnalyzer ShortLived { get; private set; } = null!;
    public static ScoreEngine ScoreEngine { get; private set; } = null!;
    public static string DataRoot { get; private set; } = null!;

    /// <summary>Execução a abrir ao iniciar (vinda de notificação do coletor).</summary>
    public static Guid? PendingExecutionToOpen { get; set; }

    public static void Initialize(string[] args)
    {
        DataRoot = DataRootManager.ResolveDataRoot();
        Directory.CreateDirectory(DataRoot);
        Settings = RadarSettings.LoadOrDefault(Path.Combine(DataRoot, "settings.json"));
        Settings.DataRoot = DataRoot;
        Store = new SqliteEventStore(Settings.DatabasePath);
        Lists = CuratedLists.LoadOrDefault(Settings.CuratedListsPath);
        ShortLived = new ShortLivedAnalyzer(Lists);
        ScoreEngine = new ScoreEngine(Settings.ScoreWeights);

        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--execution" && Guid.TryParseExact(args[i + 1], "N", out var id))
                PendingExecutionToOpen = id;
        }
    }

    public static void SaveSettings() => Settings.Save();

    public static HealthSnapshot? ReadHealth()
    {
        try
        {
            var path = Path.Combine(DataRoot, "health.json");
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<HealthSnapshot>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    public static void SendCollectorCommand(string command)
    {
        try
        {
            File.WriteAllText(Path.Combine(DataRoot, "collector.command"), command);
        }
        catch { }
    }

    public static bool CollectorIsRunning => ReadHealth() is { Running: true } h && h.IsFresh;

    public static void StartCollector()
    {
        if (CollectorIsRunning) return;
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "Radar.Collector.exe"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
                @"..\..\..\..\..\Radar.Collector\bin\Debug\net10.0-windows10.0.19041.0\Radar.Collector.exe")),
        };
        var exe = candidates.FirstOrDefault(File.Exists);
        if (exe is null) return;
        try
        {
            // --elevate: o coletor (manifest asInvoker) se relança pelo UAC para a coleta completa;
            // se o usuário cancelar o UAC, ele mesmo segue em modo degradado.
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = exe,
                Arguments = "--elevate",
                UseShellExecute = true,
            });
        }
        catch
        {
            // falha ao iniciar; segue sem coletor
        }
    }

    /// <summary>Inicialização junto ao Windows via chave Run do usuário.</summary>
    public static void SetStartWithWindows(bool enable)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: true);
            if (key is null) return;
            if (enable)
            {
                var exe = Path.Combine(AppContext.BaseDirectory, "Radar.Collector.exe");
                if (File.Exists(exe)) key.SetValue("RadarCollector", $"\"{exe}\"");
            }
            else
            {
                key.DeleteValue("RadarCollector", throwOnMissingValue: false);
            }
        }
        catch { }
    }
}
