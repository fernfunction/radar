using Radar.Core.Catalog;
using Radar.Core.Model;

namespace Radar.Core.Analysis;

/// <summary>Pistas externas resolvidas pelo coletor para enriquecer a atribuição (tarefa, serviço, run key).</summary>
public sealed record OriginHints
{
    /// <summary>Nome da tarefa agendada que corresponde ao binário/horário, quando resolvível.</summary>
    public string? ScheduledTaskName { get; init; }
    public DateTimeOffset? ScheduledTaskInstalledUtc { get; init; }
    public string? ServiceName { get; init; }
    public DateTimeOffset? ServiceInstalledUtc { get; init; }
    /// <summary>Persistência (Run/RunOnce/Startup) que aponta para este binário.</summary>
    public string? RunKeyName { get; init; }
    public DateTimeOffset? RunKeyInstalledUtc { get; init; }
    /// <summary>O pai declarado já estava morto quando o filho nasceu.</summary>
    public bool ParentDiedBeforeChild { get; init; }
    /// <summary>Script sendo executado pelo host (wscript/cscript), quando extraível da linha de comando.</summary>
    public string? ScriptFile { get; init; }
}

/// <summary>
/// Traduz a cadeia de pais em uma frase compreensível: "quem/o quê disparou e por quê".
/// </summary>
public sealed class OriginAttributor(CuratedLists? lists = null)
{
    private readonly CuratedLists _lists = lists ?? CuratedLists.Default;

    public OriginAttribution Attribute(ProcessExecution exec, OriginHints? hints = null)
    {
        hints ??= new OriginHints();
        var creator = FileNameLower(exec.CreatorImage ?? exec.DeclaredParentImage);
        var account = DescribeAccount(exec.Security);
        bool forged = exec.CreatorPid != 0 && exec.DeclaredParentPid != 0 && exec.CreatorPid != exec.DeclaredParentPid;

        // Pai forjado tem precedência: é sinal forte e raro.
        if (forged)
        {
            return new OriginAttribution
            {
                Origin = LaunchOrigin.ForgedParent,
                Description = $"Forged parent: the real creator ({FileNameLower(exec.CreatorImage)}, PID {exec.CreatorPid}) differs from the declared parent " +
                              $"({FileNameLower(exec.DeclaredParentImage)}, PID {exec.DeclaredParentPid}). {account}",
                ParentForged = true,
                ParentDiedBeforeChild = hints.ParentDiedBeforeChild,
            };
        }

        if (hints.ScheduledTaskName is { } task)
        {
            return Make(LaunchOrigin.ScheduledTask,
                $"Launched by Task Scheduler - task \"{task}\". {account}",
                task, hints.ScheduledTaskInstalledUtc, hints);
        }

        if (hints.ServiceName is { } svc)
        {
            return Make(LaunchOrigin.Service,
                $"Launched as service \"{svc}\". {account}",
                svc, hints.ServiceInstalledUtc, hints);
        }

        if (hints.RunKeyName is { } runKey)
        {
            var installed = hints.RunKeyInstalledUtc is { } d ? $" installed on {d.ToLocalTime():dd/MM/yyyy}" : string.Empty;
            return Make(LaunchOrigin.RunKeyOrStartup,
                $"Launched by startup key \"{runKey}\"{installed}. {account}",
                runKey, hints.RunKeyInstalledUtc, hints);
        }

        switch (creator)
        {
            case "explorer.exe":
                return Make(LaunchOrigin.UserExplorer,
                    $"Launched by the user via Explorer (double-click or Start menu). {account}", null, null, hints);

            case "cmd.exe" or "powershell.exe" or "pwsh.exe" or "windowsterminal.exe" or "wt.exe" or "conhost.exe":
                return Make(LaunchOrigin.UserCommandLine,
                    $"Launched from an interactive command line ({creator}). {account}", null, null, hints);

            case "wmiprvse.exe":
                return Make(LaunchOrigin.Wmi,
                    $"Launched via WMI (WmiPrvSE) - includes WMI event subscriptions, an advanced persistence. {account}",
                    null, null, hints);

            case "services.exe":
                return Make(LaunchOrigin.Service,
                    $"Launched by the service manager (services.exe). {account}", null, null, hints);

            case "taskeng.exe" or "taskhostw.exe":
                return Make(LaunchOrigin.ScheduledTask,
                    $"Launched by Task Scheduler. {account}", null, null, hints);

            case "wscript.exe" or "cscript.exe" or "mshta.exe":
                var script = hints.ScriptFile is { } s ? $" running \"{s}\"" : string.Empty;
                return Make(LaunchOrigin.ScriptHost,
                    $"Launched by a script host ({creator}){script}. {account}", hints.ScriptFile, null, hints);
        }

        if (creator is not null && _lists.DocumentHostProcesses.Contains(creator))
        {
            var kind = creator switch
            {
                "winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "msaccess.exe" or "onenote.exe"
                    => LaunchOrigin.OfficeProcess,
                "chrome.exe" or "msedge.exe" or "firefox.exe" or "brave.exe" or "opera.exe"
                    => LaunchOrigin.Browser,
                _ => LaunchOrigin.OfficeProcess,
            };
            var label = kind == LaunchOrigin.Browser ? "by the browser" : "by an Office macro/process or document app";
            return Make(kind, $"Launched {label} ({creator}). {account}", null, null, hints);
        }

        if (hints.ParentDiedBeforeChild)
        {
            return Make(LaunchOrigin.Orphaned,
                $"Orphan: the parent process exited before the child - a disposable-chain pattern. {account}", null, null, hints);
        }

        if (creator is null)
        {
            return Make(LaunchOrigin.Unknown, $"Origin not determined (unknown parent). {account}", null, null, hints);
        }

        return Make(LaunchOrigin.SystemComponent, $"Launched by {creator}. {account}", null, null, hints);
    }

    private static OriginAttribution Make(LaunchOrigin origin, string description, string? mechanism,
        DateTimeOffset? installed, OriginHints hints) => new()
    {
        Origin = origin,
        Description = description,
        MechanismName = mechanism,
        MechanismInstalledUtc = installed,
        ParentDiedBeforeChild = hints.ParentDiedBeforeChild,
    };

    /// <summary>Conta de origem sempre incluída na evidência.</summary>
    public static string DescribeAccount(SecurityContext security) => security.AccountKind switch
    {
        AccountKind.InteractiveUser => $"Account: interactive local user ({security.UserName ?? "?"}).",
        AccountKind.System => "Account: SYSTEM.",
        AccountKind.LocalService => "Account: Local Service.",
        AccountKind.NetworkService => "Account: Network Service.",
        AccountKind.OtherLocalUser => $"Account: ANOTHER user of this machine ({security.UserName ?? "?"}).",
        AccountKind.ServiceAccount => $"Service account ({security.UserName ?? "?"}).",
        _ => $"Account: unknown ({security.UserName ?? "?"}).",
    };

    private static string? FileNameLower(string? path) =>
        string.IsNullOrEmpty(path) ? null : Path.GetFileName(path).ToLowerInvariant();
}
