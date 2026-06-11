using Microsoft.UI;
using Microsoft.UI.Xaml.Media;
using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.App.Services;

/// <summary>Formatação e cores compartilhadas pelas vistas.</summary>
public static class Format
{
    public static string Bytes(long bytes) => ScoreEngine.FormatBytes(bytes);
    public static string Duration(TimeSpan? d) => ScoreEngine.FormatDuration(d);
    public static string Local(DateTimeOffset utc) => utc.ToLocalTime().ToString("dd/MM HH:mm:ss");
    public static string LocalLong(DateTimeOffset? utc) =>
        utc?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss.fff") ?? "-";

    public static string BandName(ScoreBand band) => I18n.T(band switch
    {
        ScoreBand.Critical => "Crítico",
        ScoreBand.Suspicious => "Suspeito",
        ScoreBand.Attention => "Atenção",
        _ => "Informativo",
    });

    public static SolidColorBrush BandBrush(ScoreBand band) => band switch
    {
        ScoreBand.Critical => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xC5, 0x0F, 0x1F)),
        ScoreBand.Suspicious => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xCA, 0x50, 0x10)),
        ScoreBand.Attention => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x98, 0x6F, 0x0B)),
        _ => new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x10, 0x7C, 0x10)),
    };

    public static SolidColorBrush ScoreBrush(int score) => BandBrush(SuspicionScore.BandFor(score));

    public static string SignatureName(SignatureStatus status) => I18n.T(status switch
    {
        SignatureStatus.SignedTrusted => "Assinado e confiável",
        SignatureStatus.SignedWithCaveats => "Assinado com ressalvas",
        SignatureStatus.SignedInvalid => "Assinatura INVÁLIDA (alterado)",
        SignatureStatus.SignedRevoked => "Certificado REVOGADO",
        SignatureStatus.SelfSigned => "Auto-assinado",
        SignatureStatus.Unsigned => "Não assinado",
        _ => "Verificação pendente",
    });

    public static SolidColorBrush SignatureBrush(SignatureStatus status) => status switch
    {
        SignatureStatus.SignedInvalid or SignatureStatus.SignedRevoked =>
            new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xC5, 0x0F, 0x1F)),
        SignatureStatus.Unsigned or SignatureStatus.SelfSigned =>
            new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0xCA, 0x50, 0x10)),
        SignatureStatus.SignedWithCaveats =>
            new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x98, 0x6F, 0x0B)),
        SignatureStatus.SignedTrusted =>
            new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x10, 0x7C, 0x10)),
        _ => new SolidColorBrush(Colors.Gray),
    };

    public static string TimelineGlyph(TimelineEventKind kind) => kind switch
    {
        TimelineEventKind.ProcessStart => "",          // play
        TimelineEventKind.ProcessEnd => "",            // stop
        TimelineEventKind.FirstNetworkConnection => "",// network
        TimelineEventKind.ExecutableDrop => "",        // download
        TimelineEventKind.PersistenceInstalled => "",  // repeat
        TimelineEventKind.FirstRunOfNewBinary => "",   // flag
        TimelineEventKind.SystemMarker => "",          // power
        TimelineEventKind.SensitiveRead => "",         // lock
        TimelineEventKind.SelfDelete => "",            // delete
        _ => "",
    };
}
