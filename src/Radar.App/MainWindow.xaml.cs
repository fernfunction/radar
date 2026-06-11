using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Radar.App.Pages;
using Radar.App.Services;

namespace Radar.App;

public sealed partial class MainWindow : Window
{
    private readonly DispatcherQueueTimer _healthTimer;

    public MainWindow()
    {
        InitializeComponent();
        Title = "Radar";

        var iconPath = Path.Combine(AppContext.BaseDirectory, "radar.ico");
        if (File.Exists(iconPath))
            AppWindow.SetIcon(iconPath);

        ApplyLabels();
        ContentFrame.Navigated += (_, _) => Nav.IsBackEnabled = ContentFrame.CanGoBack;
        ContentFrame.Navigate(typeof(DashboardPage));
        Nav.SelectedItem = NavDashboard;

        _healthTimer = DispatcherQueue.CreateTimer();
        _healthTimer.Interval = TimeSpan.FromSeconds(4);
        _healthTimer.Tick += (_, _) => RefreshCollectorStatus();
        _healthTimer.Start();
        RefreshCollectorStatus();

        Closed += OnClosed;

        if (AppServices.PendingExecutionToOpen is { } pending)
        {
            ContentFrame.Navigate(typeof(DossierPage), pending);
        }
        else if (!AppServices.Settings.FirstRunCompleted && Content is FrameworkElement root)
        {
            void OnRootLoaded(object s, RoutedEventArgs e)
            {
                root.Loaded -= OnRootLoaded;
                if (root.XamlRoot is { } xamlRoot)
                    _ = FirstRunAssistant.ShowAsync(xamlRoot);
            }
            root.Loaded += OnRootLoaded;
        }

        AppServices.SendCollectorCommand("ack-critical");
    }

    private void ApplyLabels()
    {
        NavDashboard.Content = I18n.T("Painel");
        NavTimeline.Content = I18n.T("Linha do tempo");
        NavShortLived.Content = I18n.T("Vida curta");
        NavSignatures.Content = I18n.T("Assinaturas");
        NavNetwork.Content = I18n.T("Rede");
        NavPersistence.Content = I18n.T("Persistência");
        NavTree.Content = I18n.T("Árvore de processos");
        NavSearch.Content = I18n.T("Busca");
        NavSettings.Content = I18n.T("Configurações");
    }

    public void Navigate(Type page, object? parameter = null) => ContentFrame.Navigate(page, parameter);

    public void OpenDossier(Guid executionId) => ContentFrame.Navigate(typeof(DossierPage), executionId);

    private void Nav_BackRequested(NavigationView sender, NavigationViewBackRequestedEventArgs args) => NavigateBack();

    private void BackAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        => args.Handled = NavigateBack();

    /// <summary>Volta da sub-view de detalhe para a view principal de origem.</summary>
    private bool NavigateBack()
    {
        if (!ContentFrame.CanGoBack) return false;
        ContentFrame.GoBack();
        return true;
    }

    /// <summary>
    /// Reaplica o idioma sem reiniciar: re-rotula o menu e re-navega a página atual
    /// (os strings de markup {loc:Loc} são reavaliados no recarregamento da página).
    /// </summary>
    public void ReapplyLanguage()
    {
        ApplyLabels();
        RefreshCollectorStatus();
        if (ContentFrame.CurrentSourcePageType is { } current)
        {
            ContentFrame.Navigate(current);
            ContentFrame.BackStack.Clear();
            Nav.IsBackEnabled = false;
        }
    }

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem item) return;
        var page = (item.Tag as string) switch
        {
            "dashboard" => typeof(DashboardPage),
            "timeline" => typeof(TimelinePage),
            "shortlived" => typeof(ShortLivedPage),
            "signatures" => typeof(SignaturesPage),
            "network" => typeof(NetworkPage),
            "persistence" => typeof(PersistencePage),
            "tree" => typeof(ProcessTreePage),
            "search" => typeof(SearchPage),
            "settings" => typeof(SettingsPage),
            _ => null,
        };
        if (page is not null && ContentFrame.CurrentSourcePageType != page)
        {
            ContentFrame.Navigate(page);
            // As vistas principais não empilham: o Voltar serve só para sair de uma sub-view de detalhe.
            ContentFrame.BackStack.Clear();
            Nav.IsBackEnabled = false;
        }
    }

    private void RefreshCollectorStatus()
    {
        var health = AppServices.ReadHealth();
        var running = health is { Running: true } && health.IsFresh;
        NavCollector.Content = running
            ? health!.Paused ? I18n.T("Coleta pausada") : I18n.T("Coleta ativa")
            : I18n.T("Coleta parada");
        CollectorGlyph.Glyph = running ? (health!.Paused ? "" : "") : "";
    }

    private async void Collector_Tapped(object sender, RoutedEventArgs e)
    {
        var health = AppServices.ReadHealth();
        var running = health is { Running: true } && health.IsFresh;
        if (!running)
        {
            AppServices.StartCollector();
            await Task.Delay(1500);
            RefreshCollectorStatus();
            return;
        }
        AppServices.SendCollectorCommand(health!.Paused ? "resume" : "pause");
        await Task.Delay(2500);
        RefreshCollectorStatus();
    }

    private void OnClosed(object sender, WindowEventArgs args)
    {
        if (AppServices.Settings.StopCollectorOnUiClose)
            AppServices.SendCollectorCommand("stop");
    }
}
