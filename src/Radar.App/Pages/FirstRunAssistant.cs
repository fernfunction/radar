using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Radar.App.Services;
using Radar.Core.Configuration;
using Radar.Core.Model;

namespace Radar.App.Pages;

/// <summary>
/// Assistente de primeiro uso: explica o que será coletado, apresenta os controles de
/// coleta, confirma o local de armazenamento e oferece habilitar a auditoria 4688 do Windows.
/// </summary>
public static class FirstRunAssistant
{
    public static async Task ShowAsync(XamlRoot xamlRoot)
    {
        var settings = AppServices.Settings;

        var panel = new StackPanel { Spacing = 12, MaxWidth = 560 };
        panel.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Text = I18n.T("O Radar registra continuamente o ciclo de vida de processos (criação, atividade, término) para dar visibilidade a programas de vida curta que passam despercebidos. Toda coleta e análise acontece NESTA máquina; nada é enviado para fora sem seu opt-in explícito."),
        });
        panel.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Text = string.Format(
                I18n.T("Os dados (banco de eventos, configurações e logs) ficam em:\n{0}\nVocê pode mudar o local e desligar qualquer módulo de coleta nas Configurações."),
                settings.DataRoot),
        });

        var profileCombo = new ComboBox
        {
            Header = I18n.T("Perfil de coleta inicial"),
            ItemsSource = new[] { I18n.T("Completo"), I18n.T("Equilibrado (recomendado)"), I18n.T("Mínimo") },
            SelectedIndex = 1,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        panel.Children.Add(profileCombo);

        var startWithWindows = new CheckBox { Content = I18n.T("Iniciar a coleta junto com o Windows"), IsChecked = false };
        panel.Children.Add(startWithWindows);

        var enableAudit = new CheckBox
        {
            Content = I18n.T("Habilitar a auditoria de criação de processos do Windows (evento 4688) como fonte complementar. Requer elevação."),
            IsChecked = false,
        };
        panel.Children.Add(enableAudit);

        panel.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.7,
            Text = I18n.T("Limitações que o Radar declara abertamente: não é antivírus, não bloqueia nem remove; score alto não é veredito de malware; malware com privilégio de kernel pode cegar qualquer monitor em user-mode, inclusive este."),
        });

        var dialog = new ContentDialog
        {
            Title = I18n.T("Bem-vindo ao Radar"),
            Content = new ScrollViewer { Content = panel },
            PrimaryButtonText = I18n.T("Começar"),
            CloseButtonText = I18n.T("Agora não"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = xamlRoot,
        };

        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
        {
            settings.Profile = profileCombo.SelectedIndex switch
            {
                0 => CollectionProfile.Complete,
                2 => CollectionProfile.Minimal,
                _ => CollectionProfile.Balanced,
            };
            settings.Modules = RadarSettings.DefaultsFor(settings.Profile);
            settings.StartCollectorWithWindows = startWithWindows.IsChecked == true;
            AppServices.SetStartWithWindows(settings.StartCollectorWithWindows);

            if (enableAudit.IsChecked == true)
                Radar.Windows.EventLogIngestor.TryEnableProcessAuditing(out _);

            AppServices.StartCollector();
        }

        settings.FirstRunCompleted = true;
        AppServices.SaveSettings();
    }
}
