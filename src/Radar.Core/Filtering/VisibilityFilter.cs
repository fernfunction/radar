using Radar.Core.Analysis;
using Radar.Core.Catalog;
using Radar.Core.Model;

namespace Radar.Core.Filtering;

/// <summary>
/// Entrada da lista de confiança do usuário: allowlist por hash + caminho + emissor,
/// nunca apenas por nome.
/// </summary>
public sealed record TrustListEntry
{
    public required string Sha256 { get; init; }
    public required string Path { get; init; }
    public string? SignerSubject { get; init; }
    public DateTimeOffset AddedUtc { get; init; }
    public string? Note { get; init; }

    public bool Matches(BinaryIdentity binary) =>
        binary.Sha256 is { } hash &&
        hash.Equals(Sha256, StringComparison.OrdinalIgnoreCase) &&
        binary.Path.Equals(Path, StringComparison.OrdinalIgnoreCase) &&
        (SignerSubject is null ||
         string.Equals(binary.Signature.Subject, SignerSubject, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Por que um processo foi excluído ou trazido de volta ao radar.</summary>
public sealed record VisibilityDecision
{
    public required bool Visible { get; init; }
    /// <summary>Era excluível por padrão (confiável), independente de ter voltado por exceção.</summary>
    public bool TrustedByDefault { get; init; }
    public required string Reason { get; init; }
}

/// <summary>
/// Implementa exclusões padrão, exceções que trazem
/// confiáveis de volta (LOLBins, linha de comando suspeita, pai improvável, módulos
/// não assinados) e os três modos de visibilidade.
/// </summary>
public sealed class VisibilityFilter(
    CuratedLists? lists = null,
    CommandLineAnalyzer? commandLineAnalyzer = null)
{
    private readonly CuratedLists _lists = lists ?? CuratedLists.Default;
    private readonly CommandLineAnalyzer _cmdline = commandLineAnalyzer ?? new CommandLineAnalyzer(lists);

    /// <summary>Caminhos dos componentes da própria aplicação.</summary>
    public HashSet<string> OwnComponentPaths { get; } = new(StringComparer.OrdinalIgnoreCase);

    public VisibilityDecision Decide(
        ProcessExecution exec,
        IReadOnlyCollection<TrustListEntry> trustList,
        bool isProtectedProcess = false,
        bool loadedUnsignedModuleFromWritableDir = false)
    {
        if (isProtectedProcess)
            return new VisibilityDecision { Visible = false, TrustedByDefault = true, Reason = "Protected Process/PPL: the user cannot act on it; tracking it only generates noise." };

        if (OwnComponentPaths.Contains(exec.Binary.Path))
            return new VisibilityDecision { Visible = false, TrustedByDefault = true, Reason = "Component of the application itself." };

        bool msSystemBinary = exec.Binary.Signature is { Status: SignatureStatus.SignedTrusted, IsMicrosoftRoot: true } &&
                              IsInProtectedSystemDir(exec.Binary.Path);
        bool userTrusted = trustList.Any(t => t.Matches(exec.Binary));
        bool trustedByDefault = msSystemBinary || userTrusted;

        if (!trustedByDefault)
            return new VisibilityDecision { Visible = true, Reason = "Does not meet the exclusion criteria - stays on the radar." };

        var fileName = exec.Binary.FileName;
        var cmdFindings = _cmdline.Analyze(fileName, exec.CommandLine);
        if (_lists.LolBins.Contains(fileName) && cmdFindings.Suspicious)
            return Back($"LOLBin with an anomalous pattern: {cmdFindings.Summary}");
        if (_lists.ShellAndScriptHosts.Contains(fileName) && cmdFindings.Suspicious)
            return Back($"Script/shell host with a suspicious command line: {cmdFindings.Summary}");
        if (ScoreEngine.IsUnlikelyParent(exec))
            return Back($"Launched by an unlikely parent ({System.IO.Path.GetFileName(exec.CreatorImage ?? "?")}).");
        if (loadedUnsignedModuleFromWritableDir)
            return Back("Loaded an unsigned module from a user-writable directory.");

        var why = msSystemBinary
            ? "Signed by Microsoft with a valid chain, residing in a system directory."
            : "On the user's trust list (hash + path + signer).";
        return new VisibilityDecision { Visible = false, TrustedByDefault = true, Reason = why };

        static VisibilityDecision Back(string reason) => new()
        {
            Visible = true,
            TrustedByDefault = true,
            Reason = $"Trusted brought back to the radar: {reason}",
        };
    }

    /// <summary>Aplica o modo de visibilidade sobre a decisão por processo.</summary>
    public static bool PassesMode(VisibilityMode mode, VisibilityDecision decision, SuspicionScore? score,
        int quarantineThreshold = 50)
        => mode switch
        {
            VisibilityMode.Focus => decision.Visible,
            VisibilityMode.Audit => true, // tudo; a decisão vira marcação visual
            VisibilityMode.AttentionQuarantine => (score?.Muted != true ? score?.Total ?? 0 : 0) >= quarantineThreshold,
            _ => decision.Visible,
        };

    public static bool IsInProtectedSystemDir(string path)
    {
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windir)) windir = @"C:\Windows";
        var normalized = path.TrimEnd('\\');
        return normalized.StartsWith(System.IO.Path.Combine(windir, "System32"), StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith(System.IO.Path.Combine(windir, "SysWOW64"), StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith(System.IO.Path.Combine(windir, "WinSxS"), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Diretórios graváveis pelo usuário (%TEMP%, Downloads, AppData, públicos, Lixeira).</summary>
    public static bool IsUserWritableDirectory(string path)
    {
        var lower = path.ToLowerInvariant();
        return lower.Contains(@"\appdata\") ||
               lower.Contains(@"\temp\") || lower.EndsWith(@"\temp", StringComparison.Ordinal) ||
               lower.Contains(@"\downloads\") || lower.EndsWith(@"\downloads", StringComparison.Ordinal) ||
               lower.Contains(@"\users\public\") ||
               lower.Contains(@"\$recycle.bin\") ||
               lower.Contains(@"\programdata\") ||
               lower.StartsWith(@"c:\temp", StringComparison.Ordinal) ||
               lower.StartsWith(@"c:\tmp", StringComparison.Ordinal);
    }
}
