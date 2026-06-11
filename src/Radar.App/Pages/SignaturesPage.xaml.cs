using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Radar.App.Services;
using Radar.Core.Abstractions;
using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.App.Pages;

public sealed class SignatureRow
{
    public Guid ExecutionId { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public string StateName { get; init; } = string.Empty;
    public Brush StateBrush { get; init; } = null!;
    public string SignerInfo { get; init; } = string.Empty;
    public string MasqueradeWarning { get; init; } = string.Empty;
    public string When { get; init; } = string.Empty;
}

public sealed class RareIssuerRow
{
    public string Issuer { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
}

/// <summary>
/// Vista de Assinaturas e Masquerading: agrupada por estado, com emissor/cadeia e
/// estatística de emissores raros na máquina.
/// </summary>
public sealed partial class SignaturesPage : Page
{
    public SignaturesPage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void Filters_Changed(object sender, object e) => LoadData();

    private void LoadData()
    {
        if (BinariesList is null) return;
        TitleText.Text = I18n.T("Assinaturas");

        var days = PeriodCombo.SelectedIndex switch { 0 => 1, 2 => 30, _ => 7 };
        var executions = AppServices.Store.QueryExecutions(new ExecutionQuery
        {
            FromUtc = DateTimeOffset.UtcNow.AddDays(-days),
            Limit = 10_000,
        });

        // Uma linha por binário (a execução mais recente)
        var byBinary = executions
            .GroupBy(e => e.Binary.Sha256 ?? e.Binary.Path.ToLowerInvariant())
            .Select(g => g.OrderByDescending(e => e.CreatedUtc).First())
            .ToList();

        SignatureStatus? filter = StateCombo.SelectedIndex switch
        {
            1 => SignatureStatus.SignedInvalid,
            2 => SignatureStatus.SignedRevoked,
            3 => SignatureStatus.Unsigned,
            4 => SignatureStatus.SelfSigned,
            5 => SignatureStatus.SignedWithCaveats,
            6 => SignatureStatus.SignedTrusted,
            _ => null,
        };

        var visible = byBinary.Where(e => filter is { } f
            ? e.Binary.Signature.Status == f
            // "dignos de atenção": tudo menos confiáveis sem masquerading
            : e.Binary.Signature.Status != SignatureStatus.SignedTrusted ||
              HasMasqueradeSignal(e));

        BinariesList.ItemsSource = visible
            .OrderByDescending(e => RankOf(e.Binary.Signature.Status))
            .ThenByDescending(e => e.CreatedUtc)
            .Take(500)
            .Select(e => new SignatureRow
            {
                ExecutionId = e.ExecutionId,
                Name = e.Binary.FileName,
                Path = e.Binary.Path,
                StateName = Format.SignatureName(e.Binary.Signature.Status),
                StateBrush = Format.SignatureBrush(e.Binary.Signature.Status),
                SignerInfo = ComposeSignerInfo(e.Binary.Signature),
                MasqueradeWarning = HasMasqueradeSignal(e) ? "⚠ masquerading" : string.Empty,
                When = Format.Local(e.CreatedUtc),
            })
            .ToList();

        // Emissores raros: assinam ≤ 2 binários distintos no período
        RareIssuersList.ItemsSource = byBinary
            .Where(e => e.Binary.Signature.Subject is { Length: > 0 } &&
                        e.Binary.Signature.Status != SignatureStatus.Unsigned)
            .GroupBy(e => e.Binary.Signature.Subject!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(x => x.Binary.Sha256).Distinct().Count() <= 2)
            .OrderBy(g => g.Count())
            .Take(8)
            .Select(g => new RareIssuerRow
            {
                Issuer = g.Key,
                Detail = $"{g.Count()} binary(ies): {string.Join(", ", g.Select(x => x.Binary.FileName).Distinct().Take(3))}",
            })
            .ToList();
    }

    private static bool HasMasqueradeSignal(ProcessExecution e) =>
        e.Score?.Signals.Any(s => s.Kind == SignalKind.Masquerading) == true;

    private static int RankOf(SignatureStatus status) => status switch
    {
        SignatureStatus.SignedInvalid or SignatureStatus.SignedRevoked => 5,
        SignatureStatus.Unsigned => 4,
        SignatureStatus.SelfSigned => 3,
        SignatureStatus.SignedWithCaveats => 2,
        SignatureStatus.Unknown => 1,
        _ => 0,
    };

    private static string ComposeSignerInfo(SignatureInfo sig)
    {
        if (sig.Status is SignatureStatus.Unsigned or SignatureStatus.Unknown) return string.Empty;
        var parts = new List<string>();
        if (sig.Subject is { } s) parts.Add($"Subject: {s}");
        if (sig.Issuer is { } i) parts.Add($"Issuer: {i}");
        if (sig.NotAfter is { } na) parts.Add($"valid until {na.ToLocalTime():dd/MM/yyyy}");
        if (sig.IsCatalogSigned) parts.Add("catalog signature");
        if (sig.Details is { } d) parts.Add(d);
        return string.Join(" · ", parts);
    }

    private void Row_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is Guid id)
            App.Window?.OpenDossier(id);
    }
}
