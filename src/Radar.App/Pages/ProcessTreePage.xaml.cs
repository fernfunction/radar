using Microsoft.UI.Xaml.Controls;
using Radar.App.Services;
using Radar.Core.Abstractions;
using Radar.Core.Model;

namespace Radar.App.Pages;

/// <summary>
/// Árvore de processos histórica: linhagem navegável incluindo processos mortos,
/// reconstruída do banco pelos vínculos pai→filho capturados na criação.
/// </summary>
public sealed partial class ProcessTreePage : Page
{
    public ProcessTreePage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadData();
    }

    private void Filters_Changed(object sender, object e) => LoadData();

    private void LoadData()
    {
        if (Tree is null) return;
        TitleText.Text = I18n.T("Árvore de processos");

        var days = PeriodCombo.SelectedIndex == 1 ? 7 : 1;
        var executions = AppServices.Store.QueryExecutions(new ExecutionQuery
        {
            FromUtc = DateTimeOffset.UtcNow.AddDays(-days),
            Limit = 5000,
        });

        var byId = executions.ToDictionary(e => e.ExecutionId);
        var childrenOf = executions
            .Where(e => e.ParentExecutionId is { } p && byId.ContainsKey(p))
            .ToLookup(e => e.ParentExecutionId!.Value);

        Tree.RootNodes.Clear();
        var roots = executions
            .Where(e => e.ParentExecutionId is not { } p || !byId.ContainsKey(p))
            .OrderByDescending(e => e.Score?.Muted == true ? 0 : e.Score?.Total ?? 0)
            .ThenByDescending(e => e.CreatedUtc)
            .Take(300);

        foreach (var root in roots)
            Tree.RootNodes.Add(BuildNode(root, childrenOf, depth: 0));
    }

    private TreeViewNode BuildNode(ProcessExecution exec,
        ILookup<Guid, ProcessExecution> childrenOf, int depth)
    {
        var score = exec.Score?.Muted == true ? 0 : exec.Score?.Total ?? 0;
        var state = exec.IsAlive ? "● alive" : $"† {Format.Duration(exec.Duration)}";
        var label = $"{exec.Binary.FileName}  (PID {exec.Pid}, {state}" +
                    (score > 0 ? $", score {score}" : string.Empty) + $")  {Format.Local(exec.CreatedUtc)}";
        var node = new TreeViewNode { Content = new TreeItem(exec.ExecutionId, label), IsExpanded = depth < 2 };

        if (depth < 12)
        {
            foreach (var child in childrenOf[exec.ExecutionId].OrderBy(c => c.CreatedUtc))
                node.Children.Add(BuildNode(child, childrenOf, depth + 1));
        }
        return node;
    }

    private void Tree_ItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
    {
        if ((args.InvokedItem as TreeViewNode)?.Content is TreeItem item)
            App.Window?.OpenDossier(item.ExecutionId);
    }

    public sealed record TreeItem(Guid ExecutionId, string Label)
    {
        public override string ToString() => Label;
    }
}
