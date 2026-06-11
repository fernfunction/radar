using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Radar.App.Services;
using Radar.Core.Abstractions;

namespace Radar.App.Pages;

public sealed class SearchRow
{
    public Guid ExecutionId { get; init; }
    public string Score { get; init; } = string.Empty;
    public Brush ScoreBrush { get; init; } = null!;
    public string Name { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public string When { get; init; } = string.Empty;
}

/// <summary>Busca global: nome, caminho, hash, domínio, IP, emissor, usuário.</summary>
public sealed partial class SearchPage : Page
{
    public SearchPage()
    {
        InitializeComponent();
        Loaded += (_, _) => TitleText.Text = I18n.T("Busca");
    }

    private void Search_Submitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args)
    {
        var text = args.QueryText?.Trim();
        if (string.IsNullOrEmpty(text)) return;

        var results = AppServices.Store.QueryExecutions(new ExecutionQuery
        {
            SearchText = text,
            Limit = 300,
        });

        ResultsList.ItemsSource = results.Select(e =>
        {
            var score = e.Score?.Muted == true ? 0 : e.Score?.Total ?? 0;
            return new SearchRow
            {
                ExecutionId = e.ExecutionId,
                Score = score.ToString(),
                ScoreBrush = Format.ScoreBrush(score),
                Name = e.Binary.FileName,
                Detail = $"{e.Binary.Path} · {e.Security.UserName ?? "?"} · " +
                         Format.SignatureName(e.Binary.Signature.Status),
                When = Format.Local(e.CreatedUtc),
            };
        }).ToList();
    }

    private void Result_Clicked(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is SearchRow row)
            App.Window?.OpenDossier(row.ExecutionId);
    }
}
