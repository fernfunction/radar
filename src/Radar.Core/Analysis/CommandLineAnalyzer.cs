using System.Text.RegularExpressions;
using Radar.Core.Catalog;

namespace Radar.Core.Analysis;

/// <summary>Achados sobre a linha de comando (hosts de script/LOLBins com padrão anômalo).</summary>
public sealed record CommandLineFindings
{
    public bool Suspicious => Reasons.Count > 0;
    public IReadOnlyList<string> Reasons { get; init; } = [];
    public string Summary => string.Join(" ", Reasons);
}

/// <summary>
/// Heurísticas de linha de comando: -EncodedCommand, IEX, download cradles, base64 longo,
/// ofuscação, e LOLBins fora de contexto esperado.
/// </summary>
public sealed partial class CommandLineAnalyzer(CuratedLists? lists = null)
{
    private readonly CuratedLists _lists = lists ?? CuratedLists.Default;

    [GeneratedRegex(@"[A-Za-z0-9+/]{120,}={0,2}", RegexOptions.Compiled)]
    private static partial Regex LongBase64();

    [GeneratedRegex(@"(?:https?|ftp)://", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex UrlPattern();

    [GeneratedRegex(@"\^|`|""\s*\+\s*""|\$\{?env:|\[char\]\d+|-join\s|\.replace\(", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ObfuscationMarkers();

    public CommandLineFindings Analyze(string imageFileName, string? commandLine)
    {
        var reasons = new List<string>();
        if (string.IsNullOrWhiteSpace(commandLine))
            return new CommandLineFindings { Reasons = reasons };

        var image = Path.GetFileName(imageFileName).ToLowerInvariant();
        var cl = commandLine;
        var clLower = cl.ToLowerInvariant();

        bool isShellHost = image is "powershell.exe" or "pwsh.exe" or "cmd.exe";

        if (isShellHost)
        {
            if (Regex.IsMatch(clLower, @"-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{16,}", RegexOptions.IgnoreCase))
                reasons.Add("Base64-encoded command (-EncodedCommand) - hides the real command content.");
            if (clLower.Contains("-windowstyle hidden") || clLower.Contains("-w hidden"))
                reasons.Add("Execution with a hidden window (-WindowStyle Hidden).");
            if (Regex.IsMatch(clLower, @"\biex\b|invoke-expression"))
                reasons.Add("Use of IEX/Invoke-Expression - runs text as code, a loader pattern.");
            if (Regex.IsMatch(clLower, @"downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient"))
                reasons.Add("Download cradle - downloads and runs remote content.");
            if (clLower.Contains("-nop") || clLower.Contains("-noprofile"))
                reasons.Add("Profile disabled (-NoProfile), common in stealthy automated execution.");
            if (clLower.Contains("frombase64string"))
                reasons.Add("Inline Base64 decoding (FromBase64String).");
        }

        if (image == "regsvr32.exe" && (UrlPattern().IsMatch(cl) || clLower.Contains("scrobj") || clLower.Contains("/i:")))
            reasons.Add("regsvr32 loading a remote script/object (the \"Squiblydoo\" technique).");
        if (image == "certutil.exe" && (clLower.Contains("urlcache") || clLower.Contains("-decode") || UrlPattern().IsMatch(cl)))
            reasons.Add("certutil used to download/decode a file - outside the legitimate use of certificates.");
        if (image == "mshta.exe" && (UrlPattern().IsMatch(cl) || clLower.Contains("javascript:") || clLower.Contains("vbscript:")))
            reasons.Add("mshta running remote content/inline script.");
        if (image == "rundll32.exe" && (UrlPattern().IsMatch(cl) || clLower.Contains("javascript:")))
            reasons.Add("rundll32 with a script/URL payload - outside the pattern of loading a local DLL.");
        if (image == "bitsadmin.exe" && (clLower.Contains("/transfer") || clLower.Contains("/addfile")))
            reasons.Add("bitsadmin transferring files - a stealthy download mechanism.");
        if (image == "msbuild.exe" && (clLower.Contains(".xml") || clLower.Contains(".csproj")) && !clLower.Contains("\\program files"))
            reasons.Add("msbuild building/running a project outside a development context.");
        if (image == "installutil.exe" && clLower.Contains("/u"))
            reasons.Add("installutil /U - a technique for running a payload via the uninstaller.");
        if (image is "wscript.exe" or "cscript.exe" &&
            Regex.IsMatch(clLower, @"\\(users|temp|appdata|downloads|public)\\.*\.(js|vbs|jse|vbe|wsf)"))
            reasons.Add("Script host running a file from a user-writable directory.");
        if (image == "cmstp.exe" && clLower.Contains("/s"))
            reasons.Add("cmstp in silent mode - a known UAC bypass technique.");
        if (image == "wmic.exe" && clLower.Contains("process call create"))
            reasons.Add("wmic creating a process - indirect execution via WMI.");

        if (LongBase64().IsMatch(cl))
            reasons.Add("Very long Base64 block on the command line.");
        if (isShellHost && ObfuscationMarkers().Matches(cl).Count >= 3)
            reasons.Add("Obfuscation markers (escapes, concatenation, [char], -join).");

        return new CommandLineFindings { Reasons = reasons };
    }

    /// <summary>É um LOLBin conhecido?</summary>
    public bool IsLolBin(string imageFileName) => _lists.LolBins.Contains(Path.GetFileName(imageFileName));
}
