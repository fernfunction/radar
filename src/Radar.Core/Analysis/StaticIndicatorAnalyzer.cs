using Radar.Core.Catalog;
using Radar.Core.Model;

namespace Radar.Core.Analysis;

/// <summary>
/// Indicadores estáticos leves: entropia (packing), extensão dupla, truque RLO,
/// nome com aparência aleatória.
/// </summary>
public static class StaticIndicatorAnalyzer
{
    private const char RloChar = '‮';
    private static readonly char[] DirectionalChars = ['‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩'];

    public static StaticIndicators Analyze(string filePath, Stream? content = null, CuratedLists? lists = null,
        bool hasDocumentLikeIcon = false)
    {
        lists ??= CuratedLists.Default;
        var fileName = Path.GetFileName(filePath);

        return new StaticIndicators
        {
            FileEntropy = content is null ? null : ShannonEntropy(content),
            HasDoubleExtension = HasDoubleExtension(fileName, lists),
            HasRloCharacter = fileName.IndexOfAny(DirectionalChars) >= 0 || fileName.Contains(RloChar),
            HasRandomLookingName = HasRandomLookingName(fileName),
            HasDocumentLikeIcon = hasDocumentLikeIcon,
        };
    }

    /// <summary>fatura.pdf.exe: extensão "de documento" imediatamente antes da extensão executável.</summary>
    public static bool HasDoubleExtension(string fileName, CuratedLists? lists = null)
    {
        lists ??= CuratedLists.Default;
        var ext = Path.GetExtension(fileName);
        if (!lists.DroppableExtensions.Contains(ext)) return false;
        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(fileName));
        return inner.Length > 0 && lists.DocumentExtensions.Contains(inner);
    }

    /// <summary>
    /// Nome com aparência aleatória: alta entropia de caracteres + ausência de estrutura
    /// (vogais raras, dígitos misturados) em nomes razoavelmente longos.
    /// </summary>
    public static bool HasRandomLookingName(string fileName)
    {
        var stem = Path.GetFileNameWithoutExtension(fileName);
        if (stem.Length < 8) return false;

        var letters = stem.Where(char.IsLetter).ToArray();
        if (letters.Length < 6) return stem.Count(char.IsDigit) >= stem.Length / 2;

        var vowelRatio = letters.Count(c => "aeiouAEIOU".Contains(c)) / (double)letters.Length;
        var entropy = ShannonEntropyOfText(stem.ToLowerInvariant());
        bool mixedDigits = stem.Any(char.IsDigit) && stem.Any(char.IsLetter) &&
                           stem.Count(char.IsDigit) >= 3;

        // Heurística: nomes "qjzkx8f2nva" têm vogais raras e entropia alta; nomes reais têm estrutura.
        return (vowelRatio < 0.18 && entropy > 3.0) || (entropy > 3.4 && mixedDigits);
    }

    /// <summary>Entropia de Shannon (0-8 bits/byte) de um stream. Acima de 7.2 sugere packing.</summary>
    public static double ShannonEntropy(Stream content)
    {
        var counts = new long[256];
        long total = 0;
        var buffer = new byte[81920];
        int read;
        while ((read = content.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (var i = 0; i < read; i++) counts[buffer[i]]++;
            total += read;
        }
        if (total == 0) return 0;

        double entropy = 0;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var p = count / (double)total;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static double ShannonEntropyOfText(string text)
    {
        if (text.Length == 0) return 0;
        double entropy = 0;
        foreach (var group in text.GroupBy(c => c))
        {
            var p = group.Count() / (double)text.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
