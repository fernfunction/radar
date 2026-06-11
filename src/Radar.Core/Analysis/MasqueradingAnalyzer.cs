using System.Globalization;
using System.Text;
using Radar.Core.Catalog;
using Radar.Core.Model;

namespace Radar.Core.Analysis;

/// <summary>Achados de masquerading, com evidência por achado.</summary>
public sealed record MasqueradingFindings
{
    public IReadOnlyList<string> Findings { get; init; } = [];
    public IReadOnlyList<string> Evidence { get; init; } = [];
    public bool Any => Findings.Count > 0;
    public string Summary => string.Join(" ", Findings);
}

/// <summary>Entrada para a análise de masquerading: fatos coletados sobre o binário/execução.</summary>
public sealed record MasqueradingInput
{
    public required string ImagePath { get; init; }
    public VersionMetadata Version { get; init; } = new();
    public SignatureInfo Signature { get; init; } = SignatureInfo.Unverified;
    public StaticIndicators Indicators { get; init; } = new();
    /// <summary>Hash anterior conhecido para este mesmo caminho (null = primeiro registro).</summary>
    public string? PreviousHashForPath { get; init; }
    public string? CurrentHash { get; init; }
    /// <summary>Havia um instalador assinado plausível envolvido na mudança de hash.</summary>
    public bool HashChangeExplainedByUpdate { get; init; }
    /// <summary>Pai declarado difere do criador real (parent PID spoofing, via ETW).</summary>
    public bool ParentForged { get; init; }
}

/// <summary>
/// Detecção de "se passar por outro": nome de sistema fora do lugar, typosquatting
/// com homoglyphs, metadados mentirosos, ícone de documento + extensão dupla, hash divergente
/// para mesmo caminho, pai forjado.
/// </summary>
public sealed class MasqueradingAnalyzer(CuratedLists? lists = null)
{
    private readonly CuratedLists _lists = lists ?? CuratedLists.Default;

    public MasqueradingFindings Analyze(MasqueradingInput input)
    {
        var findings = new List<string>();
        var evidence = new List<string>();
        var fileName = Path.GetFileName(input.ImagePath);
        var dir = NormalizeDir(Path.GetDirectoryName(input.ImagePath) ?? string.Empty);

        // 1. Nome de sistema fora do lugar
        if (_lists.SystemBinaryExpectedDirs.TryGetValue(fileName, out var expectedDirs))
        {
            bool inExpected = expectedDirs.Any(e => dir.StartsWith(NormalizeDir(ExpandWindowsVars(e)), StringComparison.OrdinalIgnoreCase));
            if (!inExpected)
            {
                findings.Add($"\"{fileName}\" is the name of a Windows component, but it runs outside its legitimate directory ({string.Join(" or ", expectedDirs)}).");
                evidence.Add(input.ImagePath);
            }
        }
        // 2. Typosquatting / homoglyphs (só se não for exatamente um nome conhecido)
        else
        {
            var normalized = NormalizeHomoglyphs(fileName);
            bool homoglyphHit = !fileName.Equals(normalized, StringComparison.OrdinalIgnoreCase) &&
                                _lists.WellKnownProcessNames.Contains(normalized);
            if (homoglyphHit)
            {
                findings.Add($"The name \"{fileName}\" uses look-alike characters (homoglyphs) to imitate \"{normalized}\".");
                evidence.Add(input.ImagePath);
            }
            else
            {
                foreach (var known in _lists.WellKnownProcessNames)
                {
                    var distance = DamerauLevenshtein(normalized.ToLowerInvariant(), known.ToLowerInvariant(), maxDistance: 2);
                    if (distance is 1 or 2 && Math.Abs(normalized.Length - known.Length) <= 2)
                    {
                        findings.Add($"The name \"{fileName}\" is {distance} edit(s) away from \"{known}\" - possible typosquatting.");
                        evidence.Add(input.ImagePath);
                        break;
                    }
                }
            }
        }

        // 3. Metadados mentirosos: CompanyName alega fabricante sem assinatura correspondente.
        //    Só concluímos quando a assinatura já foi verificada. Enquanto está pendente (Unknown),
        //    afirmar "não há assinatura válida" geraria falso positivo para todo binário da Microsoft
        //    na janela de verificação (cruzamento entre metadados e emissor REAL).
        if (input.Signature.Status != SignatureStatus.Unknown)
        {
            var claimed = $"{input.Version.CompanyName} {input.Version.ProductName}".ToLowerInvariant();
            foreach (var (vendor, signerHints) in _lists.VendorNameToSignerHints)
            {
                if (!claimed.Contains(vendor, StringComparison.OrdinalIgnoreCase)) continue;
                var signer = $"{input.Signature.Subject} {input.Signature.Issuer}".ToLowerInvariant();
                bool signerMatches = input.Signature.Status == SignatureStatus.SignedTrusted &&
                                     signerHints.Any(h => signer.Contains(h, StringComparison.OrdinalIgnoreCase));
                if (!signerMatches)
                {
                    findings.Add($"The metadata claims \"{input.Version.CompanyName ?? vendor}\", but there is no valid signature from the claimed vendor.");
                    evidence.Add($"CompanyName={input.Version.CompanyName}; signature={input.Signature.Status}/{input.Signature.Subject ?? "-"}");
                }
                break;
            }
        }

        // 3b. OriginalFilename divergente do nome em disco (renomeado)
        if (!string.IsNullOrWhiteSpace(input.Version.OriginalFilename) &&
            input.Version.OriginalFilename.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(input.Version.OriginalFilename, fileName, StringComparison.OrdinalIgnoreCase) &&
            _lists.WellKnownProcessNames.Contains(input.Version.OriginalFilename))
        {
            findings.Add($"The file is named \"{fileName}\" but was compiled as \"{input.Version.OriginalFilename}\" - a renamed well-known binary.");
            evidence.Add($"OriginalFilename={input.Version.OriginalFilename}");
        }

        // 4. Ícone de documento em executável + extensão dupla
        if (input.Indicators.HasDocumentLikeIcon && input.Indicators.HasDoubleExtension)
        {
            findings.Add("Executable with a document icon and a double extension - a classic disguise as a clickable \"document\".");
            evidence.Add(fileName);
        }
        else if (input.Indicators.HasRloCharacter)
        {
            findings.Add("The name contains a Unicode right-to-left override character (RLO) - it hides the real extension.");
            evidence.Add(fileName);
        }

        // 5. Hash divergente para mesmo caminho sem atualização plausível
        if (input.PreviousHashForPath is { } prev && input.CurrentHash is { } cur &&
            !prev.Equals(cur, StringComparison.OrdinalIgnoreCase) && !input.HashChangeExplainedByUpdate)
        {
            findings.Add("The binary at this path changed content (hash) with no plausible update event.");
            evidence.Add($"previous hash {Truncate(prev)} → current {Truncate(cur)}");
        }

        // 6. Pai forjado (parent PID spoofing)
        if (input.ParentForged)
        {
            findings.Add("The declared parent differs from the real creator recorded by the kernel (parent PID spoofing) - rare in legitimate software.");
            evidence.Add(input.ImagePath);
        }

        return new MasqueradingFindings { Findings = findings, Evidence = evidence };
    }

    private static string Truncate(string hash) => hash.Length > 12 ? hash[..12] + "…" : hash;

    private static string NormalizeDir(string dir) => dir.TrimEnd('\\', '/');

    private static string ExpandWindowsVars(string path) =>
        path.Replace("%windir%", Environment.GetFolderPath(Environment.SpecialFolder.Windows) is { Length: > 0 } w ? w : @"C:\Windows",
            StringComparison.OrdinalIgnoreCase);

    /// <summary>Mapa de homoglyphs comuns (dígitos parecidos + Cirílico/Grego visualmente idênticos ao Latim).</summary>
    private static readonly Dictionary<char, char> Homoglyphs = new()
    {
        ['0'] = 'o', ['1'] = 'l', ['3'] = 'e', ['5'] = 's', ['7'] = 't',
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c', ['х'] = 'x',
        ['у'] = 'y', ['і'] = 'i', ['ѕ'] = 's', ['ԁ'] = 'd', ['ɡ'] = 'g',
        ['α'] = 'a', ['ο'] = 'o', ['ν'] = 'v', ['ρ'] = 'p', ['τ'] = 't',
    };

    public static string NormalizeHomoglyphs(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var ch in name)
        {
            var lower = char.ToLowerInvariant(ch);
            sb.Append(Homoglyphs.TryGetValue(lower, out var mapped) ? mapped : lower);
        }
        // Remove marcas de combinação (ex.: "е́" não deve escapar da normalização)
        var normalized = sb.ToString().Normalize(NormalizationForm.FormD);
        var result = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.NonSpacingMark)
                result.Append(ch);
        }
        return result.ToString();
    }

    /// <summary>Distância de Damerau-Levenshtein com teto (corta cedo para desempenho).</summary>
    public static int DamerauLevenshtein(string a, string b, int maxDistance = int.MaxValue)
    {
        if (Math.Abs(a.Length - b.Length) > maxDistance) return maxDistance + 1;
        var d = new int[a.Length + 1, b.Length + 1];
        for (var i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (var j = 0; j <= b.Length; j++) d[0, j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + cost);
            }
        }
        return d[a.Length, b.Length];
    }
}
