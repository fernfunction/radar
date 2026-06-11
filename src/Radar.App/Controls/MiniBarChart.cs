using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Radar.App.Controls;

/// <summary>
/// Gráfico de barras leve em WinUI puro (sem dependências nativas). As alturas são proporcionais
/// por layout: cada coluna é um Grid de duas linhas em estrela (vazio em cima, barra embaixo),
/// então não há cálculo de medida nem timing de ActualHeight. Usado no Dashboard (atividade por
/// dia) e na Timeline (densidade de eventos por hora).
/// </summary>
public sealed class MiniBarChart : UserControl
{
    private readonly Grid _bars = new();
    private readonly Grid _labels = new();

    public Brush BarBrush { get; set; } =
        new SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 0x4C, 0x6E, 0xF5));

    public MiniBarChart()
    {
        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        Grid.SetRow(_bars, 0);
        Grid.SetRow(_labels, 1);
        _labels.Margin = new Thickness(0, 4, 0, 0);
        root.Children.Add(_bars);
        root.Children.Add(_labels);
        Content = root;
    }

    public void SetData(IReadOnlyList<double> values, IReadOnlyList<string> labels)
    {
        _bars.Children.Clear();
        _bars.ColumnDefinitions.Clear();
        _labels.Children.Clear();
        _labels.ColumnDefinitions.Clear();
        if (values.Count == 0) return;

        var max = Math.Max(1, values.Count > 0 ? values.Max() : 1);

        for (var i = 0; i < values.Count; i++)
        {
            _bars.ColumnDefinitions.Add(new ColumnDefinition());
            _labels.ColumnDefinitions.Add(new ColumnDefinition());

            var v = Math.Max(0, values[i]);
            var column = new Grid();
            column.RowDefinitions.Add(new RowDefinition { Height = new GridLength(Math.Max(0, max - v), GridUnitType.Star) });
            column.RowDefinitions.Add(new RowDefinition { Height = new GridLength(v, GridUnitType.Star) });

            var bar = new Border
            {
                Background = BarBrush,
                CornerRadius = new CornerRadius(3, 3, 0, 0),
                Margin = new Thickness(2, 0, 2, 0),
                VerticalAlignment = VerticalAlignment.Stretch,
                MinHeight = v > 0 ? 2 : 0,
            };
            ToolTipService.SetToolTip(bar, $"{labels.ElementAtOrDefault(i)}: {values[i]:0}");
            Grid.SetRow(bar, 1);
            column.Children.Add(bar);

            Grid.SetColumn(column, i);
            _bars.Children.Add(column);

            var label = new TextBlock
            {
                Text = labels.ElementAtOrDefault(i) ?? string.Empty,
                FontSize = 10,
                Opacity = 0.7,
                HorizontalAlignment = HorizontalAlignment.Center,
                TextTrimming = TextTrimming.Clip,
            };
            Grid.SetColumn(label, i);
            _labels.Children.Add(label);
        }
    }
}
