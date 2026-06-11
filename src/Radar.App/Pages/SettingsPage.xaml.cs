using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Radar.App.Services;
using Radar.Core.Configuration;
using Radar.Core.Model;
using Radar.Data;

namespace Radar.App.Pages;

/// <summary>
/// Configurações: interruptores por módulo com descrição do que se perde, exclusões de
/// coleta, raiz de dados com migração, frequências com custo estimado, ciclo de vida, privacidade.
/// </summary>
public sealed partial class SettingsPage : Page
{
    private bool _loading = true;
    private readonly Dictionary<CollectionModule, ToggleSwitch> _moduleSwitches = [];

    public SettingsPage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void LoadData()
    {
        _loading = true;
        var s = AppServices.Settings;
        TitleText.Text = I18n.T("Configurações");

        ProfileCombo.SelectedIndex = (int)s.Profile;
        ModulesPanel.Children.Clear();
        _moduleSwitches.Clear();
        foreach (var module in Enum.GetValues<CollectionModule>())
        {
            var toggle = new ToggleSwitch
            {
                Header = I18n.T(ModuleName(module)),
                IsOn = s.IsModuleEnabled(module),
            };
            toggle.Toggled += (_, _) => ModuleToggled(module, toggle.IsOn);
            _moduleSwitches[module] = toggle;
            ModulesPanel.Children.Add(toggle);
            ModulesPanel.Children.Add(new TextBlock
            {
                Text = I18n.T("Se desligado: ") + I18n.T(RadarSettings.WhatYouLose(module)),
                FontSize = 12,
                Opacity = 0.6,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, -6, 0, 6),
            });
        }

        RefreshExclusions();

        DataRootText.Text = I18n.T("Raiz atual:") + " " + s.DataRoot;
        var stats = AppServices.Store.GetStats();
        DataRootStats.Text = string.Format(
            I18n.T("Banco: {0} · {1} execuções · eventos de {2} até {3}"),
            Format.Bytes(stats.DatabaseBytes), stats.ExecutionCount,
            Format.LocalLong(stats.OldestEventUtc), Format.LocalLong(stats.NewestEventUtc));
        RetentionDays.Value = s.Retention.RawEventDays;
        RetentionMb.Value = s.Retention.MaxDatabaseMegabytes;

        RatePersistence.Value = s.Rates.PersistenceScanMinutes;
        RateSignatures.Value = s.Rates.SignatureQueueBatchSeconds;
        RateCheckpoint.Value = s.Rates.DbCheckpointSeconds;
        RateMaxToasts.Value = s.Rates.MaxNotificationsPerHour;
        UpdateRateCost();

        StopOnClose.IsOn = s.StopCollectorOnUiClose;
        StopOnCloseWarning.Visibility = s.StopCollectorOnUiClose ? Visibility.Visible : Visibility.Collapsed;
        StartWithWindows.IsOn = s.StartCollectorWithWindows;
        ToastsEnabled.IsOn = s.Notifications.ToastEnabled;
        ToastThreshold.SelectedIndex = s.Notifications.MinimumBand switch
        {
            ScoreBand.Attention => 2,
            ScoreBand.Suspicious => 1,
            _ => 0,
        };

        OptInLists.IsOn = s.OptInOnlineListUpdates;
        OptInReputation.IsOn = s.OptInHashReputation;
        LanguageCombo.SelectedIndex = s.Language.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        ShortLivedThreshold.Value = s.ShortLivedThresholdSeconds;

        _loading = false;
    }

    private static string ModuleName(CollectionModule module) => module switch
    {
        CollectionModule.Processes => "Processos (núcleo)",
        CollectionModule.Network => "Rede (TCP/UDP por processo)",
        CollectionModule.Dns => "DNS (consultas por processo)",
        CollectionModule.FileSensitiveReads => "Arquivos: leituras sensíveis",
        CollectionModule.FileDrops => "Arquivos: drops de executáveis/scripts",
        CollectionModule.FileSelfDelete => "Arquivos: detecção de auto-deleção",
        CollectionModule.ImageLoad => "Módulos / Image Load",
        CollectionModule.PersistenceScan => "Varredura de persistência",
        CollectionModule.Baseline => "Baseline e prevalência",
        _ => module.ToString(),
    };

    private void ModuleToggled(CollectionModule module, bool on)
    {
        if (_loading) return;
        var s = AppServices.Settings;
        s.Modules[module] = on;
        s.Profile = CollectionProfile.Custom;
        ProfileCombo.SelectedIndex = (int)CollectionProfile.Custom;
        AppServices.SaveSettings(); // o coletor recarrega a quente
    }

    private void Profile_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        var s = AppServices.Settings;
        s.Profile = (CollectionProfile)ProfileCombo.SelectedIndex;
        if (s.Profile != CollectionProfile.Custom)
        {
            s.Modules = RadarSettings.DefaultsFor(s.Profile);
            foreach (var (module, toggle) in _moduleSwitches)
            {
                _loading = true;
                toggle.IsOn = s.IsModuleEnabled(module);
                _loading = false;
            }
        }
        AppServices.SaveSettings();
    }

    private void RefreshExclusions()
    {
        ExclusionsList.ItemsSource = AppServices.Settings.Exclusions
            .Select(x => x.PathPrefix ?? x.SignerSubject ?? x.ProcessName ?? "?")
            .ToList();
    }

    private void AddExclusion_Click(object sender, RoutedEventArgs e)
    {
        var text = NewExclusionBox.Text?.Trim();
        if (string.IsNullOrEmpty(text)) return;
        AppServices.Settings.Exclusions.Add(text.Contains('\\') || text.Contains('/')
            ? new CollectionExclusion { PathPrefix = text }
            : text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? new CollectionExclusion { ProcessName = text }
                : new CollectionExclusion { SignerSubject = text });
        NewExclusionBox.Text = string.Empty;
        AppServices.SaveSettings();
        RefreshExclusions();
    }

    private void RemoveExclusion_Click(object sender, RoutedEventArgs e)
    {
        if (ExclusionsList.SelectedIndex is var index && index >= 0 &&
            index < AppServices.Settings.Exclusions.Count)
        {
            AppServices.Settings.Exclusions.RemoveAt(index);
            AppServices.SaveSettings();
            RefreshExclusions();
        }
    }

    private void Migrate_Click(object sender, RoutedEventArgs e)
    {
        var target = NewRootBox.Text?.Trim();
        if (string.IsNullOrEmpty(target)) return;

        var validation = DataRootManager.Validate(target);
        if (!validation.Ok)
        {
            MigrateResult.Text = "✗ " + string.Join(" ", validation.Errors);
            return;
        }
        var warnings = validation.Warnings.Count > 0 ? "⚠ " + string.Join(" ", validation.Warnings) + "\n" : string.Empty;

        // Para a coleta antes de mover o banco
        AppServices.SendCollectorCommand("stop");
        Task.Delay(2500).Wait();

        var result = DataRootManager.Migrate(AppServices.Settings.DataRoot, target);
        if (result.Success)
        {
            AppServices.Settings.DataRoot = target;
            AppServices.SaveSettings();
            MigrateResult.Text = warnings + string.Format(
                I18n.T("✓ Migração concluída ({0} arquivos). Reabra o Radar e inicie a coleta para usar a nova raiz."),
                result.FilesMoved);
        }
        else
        {
            MigrateResult.Text = I18n.T("✗ Falha na migração:") + " " + result.Error;
        }
    }

    private void Setting_Changed(object sender, object e)
    {
        if (_loading) return;
        var s = AppServices.Settings;
        s.Retention.RawEventDays = (int)RetentionDays.Value;
        s.Retention.MaxDatabaseMegabytes = (int)RetentionMb.Value;
        s.Rates.PersistenceScanMinutes = (int)RatePersistence.Value;
        s.Rates.SignatureQueueBatchSeconds = (int)RateSignatures.Value;
        s.Rates.DbCheckpointSeconds = (int)RateCheckpoint.Value;
        s.Rates.MaxNotificationsPerHour = (int)RateMaxToasts.Value;
        s.Notifications.ToastEnabled = ToastsEnabled.IsOn;
        s.Notifications.MinimumBand = ToastThreshold.SelectedIndex switch
        {
            1 => ScoreBand.Suspicious,
            2 => ScoreBand.Attention,
            _ => ScoreBand.Critical,
        };
        s.OptInOnlineListUpdates = OptInLists.IsOn;
        s.OptInHashReputation = OptInReputation.IsOn;
        s.ShortLivedThresholdSeconds = (int)ShortLivedThreshold.Value;
        AppServices.SaveSettings();
        UpdateRateCost();
    }

    /// <summary>Custo estimado da frequência escolhida.</summary>
    private void UpdateRateCost()
    {
        var scansPerDay = 1440.0 / Math.Max(5, (int)RatePersistence.Value);
        var checkpointsPerHour = 3600.0 / Math.Max(5, (int)RateCheckpoint.Value);
        RateCostHint.Text = string.Format(
            I18n.T("Custo estimado: varredura de persistência ≈{0:0} execuções/dia (CPU ~1s cada); checkpoint ≈{1:0}/hora (I/O leve). Intervalos menores = detecção mais rápida, mais CPU/I-O."),
            scansPerDay, checkpointsPerHour);
    }

    private void StopOnClose_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        AppServices.Settings.StopCollectorOnUiClose = StopOnClose.IsOn;
        StopOnCloseWarning.Visibility = StopOnClose.IsOn ? Visibility.Visible : Visibility.Collapsed;
        AppServices.SaveSettings();
    }

    private void StartWithWindows_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        AppServices.Settings.StartCollectorWithWindows = StartWithWindows.IsOn;
        AppServices.SetStartWithWindows(StartWithWindows.IsOn);
        AppServices.SaveSettings();
    }

    private void Language_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        AppServices.Settings.Language = LanguageCombo.SelectedIndex == 1 ? "en" : "pt-BR";
        AppServices.SaveSettings();
        // Reaplica o idioma de imediato: menu + re-navegação da página atual.
        App.Window?.ReapplyLanguage();
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(AppServices.Settings.LogsDirectory);
            System.Diagnostics.Process.Start("explorer.exe", $"\"{AppServices.Settings.LogsDirectory}\"");
        }
        catch { }
    }

    private void OpenSettingsJson_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            AppServices.SaveSettings();
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = AppServices.Settings.SettingsPath,
                UseShellExecute = true,
            });
        }
        catch { }
    }

    private void EnableAudit_Click(object sender, RoutedEventArgs e)
    {
        var ok = Radar.Windows.EventLogIngestor.TryEnableProcessAuditing(out var message);
        AuditResult.Text = (ok ? "✓ " : "✗ ") + message;
    }
}
