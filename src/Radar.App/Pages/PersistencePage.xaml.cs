using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Radar.App.Services;
using Radar.Core.Model;

namespace Radar.App.Pages;

public sealed class PersistenceRow
{
    public string ChangeKind { get; init; } = string.Empty;
    public Brush ChangeBrush { get; init; } = null!;
    public string Name { get; init; } = string.Empty;
    public string KindName { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public string Correlation { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public string When { get; init; } = string.Empty;
    public string OpenTarget { get; init; } = string.Empty;
}

/// <summary>
/// Persistência Correlacionada: diff temporal dos autoruns com vínculo ao instalador
/// ("a tarefa X apareceu 3s depois da execução do binário Y").
/// </summary>
public sealed partial class PersistencePage : Page
{
    public PersistencePage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void Filters_Changed(object sender, object e) => LoadData();

    private void LoadData()
    {
        if (EntriesList is null) return;
        TitleText.Text = I18n.T("Persistência");

        var days = PeriodCombo.SelectedIndex switch { 0 => 1, 2 => 30, _ => 7 };
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
        var entries = AppServices.Store.GetPersistenceEntries(includeRemoved: true);
        bool diffView = ViewCombo.SelectedIndex == 0;

        var rows = new List<PersistenceRow>();
        foreach (var entry in entries)
        {
            string change;
            global::Windows.UI.Color color;
            if (entry.RemovedUtc is { } removed && removed >= cutoff)
            {
                change = "removed";
                color = global::Windows.UI.Color.FromArgb(255, 0x60, 0x7D, 0x8B);
            }
            else if (entry.RemovedUtc is null && entry.FirstSeenUtc >= cutoff)
            {
                change = "added";
                color = global::Windows.UI.Color.FromArgb(255, 0xC5, 0x0F, 0x1F);
            }
            else if (entry.RemovedUtc is null)
            {
                change = "active";
                color = global::Windows.UI.Color.FromArgb(255, 0x10, 0x7C, 0x10);
            }
            else
            {
                continue; // removida fora da janela
            }

            if (diffView && change == "active") continue;

            var correlation = string.Empty;
            if (entry.InstallerExecutionId is { } installerId &&
                AppServices.Store.GetExecution(installerId) is { } installer)
            {
                var gap = entry.FirstSeenUtc - installer.CreatedUtc;
                correlation = $"⚠ Correlated: appeared {Format.Duration(gap)} after the execution of " +
                              $"{installer.Binary.FileName} ({Format.Local(installer.CreatedUtc)})";
            }

            rows.Add(new PersistenceRow
            {
                ChangeKind = change,
                ChangeBrush = new SolidColorBrush(color),
                Name = entry.Name,
                KindName = KindPt(entry.Kind) +
                           (entry.Signature.Status != SignatureStatus.Unknown
                               ? $" · {Format.SignatureName(entry.Signature.Status)}" : string.Empty),
                Target = entry.Target,
                Correlation = correlation,
                Location = entry.Location +
                           (entry.TriggerDescription is { } t ? $" · trigger: {t}" : string.Empty) +
                           (entry.Author is { } a ? $" · author: {a}" : string.Empty),
                When = Format.Local(entry.RemovedUtc ?? entry.FirstSeenUtc),
                OpenTarget = entry.TargetBinaryPath ?? entry.Location,
            });
        }

        EntriesList.ItemsSource = rows
            .OrderBy(r => r.ChangeKind == "active")
            .ThenByDescending(r => r.When)
            .Take(500)
            .ToList();
    }

    private static string KindPt(PersistenceKind kind) => kind switch
    {
        PersistenceKind.RunKey => "Run key",
        PersistenceKind.RunOnceKey => "RunOnce key",
        PersistenceKind.StartupFolder => "Startup folder",
        PersistenceKind.ScheduledTask => "scheduled task",
        PersistenceKind.Service => "service",
        PersistenceKind.Ifeo => "IFEO",
        PersistenceKind.AppInitDll => "AppInit DLL",
        PersistenceKind.AppCertDll => "AppCert DLL",
        PersistenceKind.ShellExtension => "shell extension",
        PersistenceKind.WmiSubscription => "WMI subscription",
        PersistenceKind.LsaProvider => "LSA provider",
        PersistenceKind.Winlogon => "Winlogon",
        _ => kind.ToString(),
    };

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not string target || target.Length == 0) return;
        try
        {
            if (File.Exists(target))
            {
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{target}\"");
            }
            else if (Directory.Exists(target))
            {
                System.Diagnostics.Process.Start("explorer.exe", $"\"{target}\"");
            }
            else
            {
                // chave de registro / caminho de tarefa: copia para a área de transferência
                var package = new global::Windows.ApplicationModel.DataTransfer.DataPackage();
                package.SetText(target);
                global::Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
            }
        }
        catch { }
    }
}
