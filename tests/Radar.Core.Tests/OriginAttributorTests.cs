using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Core.Tests;

public class OriginAttributorTests
{
    private static readonly OriginAttributor Attributor = new();

    [Fact]
    public void Explorer_parent_means_user_double_click()
    {
        var origin = Attributor.Attribute(TestData.Execution(creatorImage: @"C:\Windows\explorer.exe"));
        Assert.Equal(LaunchOrigin.UserExplorer, origin.Origin);
        Assert.Contains("Explorer", origin.Description);
        Assert.Contains("alice", origin.Description); // conta sempre em evidência
    }

    [Fact]
    public void Scheduled_task_hint_resolves_name()
    {
        var origin = Attributor.Attribute(
            TestData.Execution(creatorImage: @"C:\Windows\System32\svchost.exe"),
            new OriginHints { ScheduledTaskName = @"\Microsoft\Windows\Updater\NightlyTask" });
        Assert.Equal(LaunchOrigin.ScheduledTask, origin.Origin);
        Assert.Contains("NightlyTask", origin.Description);
        Assert.Equal(@"\Microsoft\Windows\Updater\NightlyTask", origin.MechanismName);
    }

    [Fact]
    public void Service_hint_resolves_name()
    {
        var origin = Attributor.Attribute(
            TestData.Execution(creatorImage: @"C:\Windows\System32\services.exe"),
            new OriginHints { ServiceName = "EvilSvc" });
        Assert.Equal(LaunchOrigin.Service, origin.Origin);
        Assert.Contains("EvilSvc", origin.Description);
    }

    [Fact]
    public void Forged_parent_takes_precedence()
    {
        var exec = TestData.Execution(creatorPid: 666, declaredParentPid: 100);
        var origin = Attributor.Attribute(exec,
            new OriginHints { ScheduledTaskName = "Whatever" });
        Assert.Equal(LaunchOrigin.ForgedParent, origin.Origin);
        Assert.True(origin.ParentForged);
    }

    [Fact]
    public void Office_parent_attributed_as_macro_source()
    {
        var origin = Attributor.Attribute(TestData.Execution(
            creatorImage: @"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"));
        Assert.Equal(LaunchOrigin.OfficeProcess, origin.Origin);
    }

    [Fact]
    public void Browser_parent_attributed()
    {
        var origin = Attributor.Attribute(TestData.Execution(
            creatorImage: @"C:\Program Files\Google\Chrome\Application\chrome.exe"));
        Assert.Equal(LaunchOrigin.Browser, origin.Origin);
    }

    [Fact]
    public void Script_host_includes_script_file()
    {
        var origin = Attributor.Attribute(
            TestData.Execution(creatorImage: @"C:\Windows\System32\wscript.exe"),
            new OriginHints { ScriptFile = @"C:\Users\alice\inv.vbs" });
        Assert.Equal(LaunchOrigin.ScriptHost, origin.Origin);
        Assert.Contains("inv.vbs", origin.Description);
    }

    [Fact]
    public void Wmi_parent_attributed()
    {
        var origin = Attributor.Attribute(TestData.Execution(
            creatorImage: @"C:\Windows\System32\wbem\WmiPrvSE.exe"));
        Assert.Equal(LaunchOrigin.Wmi, origin.Origin);
    }

    [Fact]
    public void Run_key_hint_attributed_with_install_date()
    {
        var installed = new DateTimeOffset(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);
        var origin = Attributor.Attribute(
            TestData.Execution(creatorImage: @"C:\Windows\explorer.exe"),
            new OriginHints { RunKeyName = @"HKCU\...\Run\Updater", RunKeyInstalledUtc = installed });
        Assert.Equal(LaunchOrigin.RunKeyOrStartup, origin.Origin);
        Assert.Contains("01/06", origin.Description);
    }

    [Fact]
    public void Orphan_detected_when_parent_died_first()
    {
        var origin = Attributor.Attribute(
            TestData.Execution(creatorImage: @"C:\Temp\stage1.exe"),
            new OriginHints { ParentDiedBeforeChild = true });
        Assert.Equal(LaunchOrigin.Orphaned, origin.Origin);
    }

    [Fact]
    public void System_account_described()
    {
        var description = OriginAttributor.DescribeAccount(new SecurityContext
        {
            AccountKind = AccountKind.System,
        });
        Assert.Contains("SYSTEM", description);
    }
}
