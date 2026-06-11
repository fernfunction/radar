using Microsoft.UI.Xaml.Markup;

namespace Radar.App.Services;

/// <summary>
/// Markup extension de localização para uso direto no XAML: <c>Text="{loc:Loc Key=Painel}"</c>.
/// Resolve via <see cref="I18n.T"/> (PT-BR é a chave-fonte; retorna a tradução no idioma ativo).
/// É avaliado no carregamento do XAML, então mudar o idioma exige recarregar a página/app. A UI
/// recria as páginas ao navegar, e o menu é reaplicado em <c>ApplyLabels</c>.
/// </summary>
public sealed partial class Loc : MarkupExtension
{
    /// <summary>Chave (texto-fonte em PT-BR) a traduzir.</summary>
    public string Key { get; set; } = string.Empty;

    protected override object ProvideValue() => I18n.T(Key);
}
