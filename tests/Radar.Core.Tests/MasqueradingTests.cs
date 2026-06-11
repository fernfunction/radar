using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Core.Tests;

public class MasqueradingTests
{
    private static readonly MasqueradingAnalyzer Analyzer = new();

    [Fact]
    public void System_name_outside_legit_dir_is_flagged()
    {
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = @"C:\Users\alice\AppData\Roaming\svchost.exe",
        });
        Assert.True(result.Any);
        Assert.Contains(result.Findings, f => f.Contains("svchost.exe"));
    }

    [Fact]
    public void System_binary_in_system32_is_clean()
    {
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = @"C:\Windows\System32\svchost.exe",
        });
        Assert.False(result.Any);
    }

    [Theory]
    [InlineData(@"C:\Temp\svch0st.exe")]   // homoglyph 0→o
    [InlineData(@"C:\Temp\lsasss.exe")]    // distância de edição 1
    [InlineData(@"C:\Temp\chrome_.exe")]   // sufixo
    public void Typosquatting_and_homoglyphs_detected(string path)
    {
        var result = Analyzer.Analyze(new MasqueradingInput { ImagePath = path });
        Assert.True(result.Any, $"esperava typosquat para {path}: {result.Summary}");
    }

    [Fact]
    public void Cyrillic_homoglyph_normalization_works()
    {
        // "сhrome" com 'с' cirílico
        var normalized = MasqueradingAnalyzer.NormalizeHomoglyphs("сhrome.exe");
        Assert.Equal("chrome.exe", normalized);
    }

    [Fact]
    public void Lying_metadata_microsoft_without_signature()
    {
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = @"C:\Users\alice\Downloads\tool.exe",
            Version = new VersionMetadata { CompanyName = "Microsoft Corporation" },
            Signature = new SignatureInfo { Status = SignatureStatus.Unsigned },
        });
        Assert.Contains(result.Findings, f => f.Contains("claims"));
    }

    [Fact]
    public void Real_microsoft_signature_passes_metadata_check()
    {
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = @"C:\Program Files\App\app.exe",
            Version = new VersionMetadata { CompanyName = "Microsoft Corporation" },
            Signature = new SignatureInfo
            {
                Status = SignatureStatus.SignedTrusted,
                Subject = "Microsoft Corporation",
                IsMicrosoftRoot = true,
            },
        });
        Assert.DoesNotContain(result.Findings, f => f.Contains("claims"));
    }

    [Fact]
    public void Pending_signature_does_not_trigger_metadata_lie()
    {
        // Enquanto a assinatura está Unknown (fila de verificação), não concluímos masquerading
        // por metadados. Senão todo binário da Microsoft pontuaria na janela de verificação.
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = @"C:\Windows\System32\conhost.exe",
            Version = new VersionMetadata { CompanyName = "Microsoft Corporation" },
            Signature = new SignatureInfo { Status = SignatureStatus.Unknown },
        });
        Assert.DoesNotContain(result.Findings, f => f.Contains("claims"));
    }

    [Fact]
    public void Renamed_known_binary_detected_via_original_filename()
    {
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = @"C:\Users\alice\Downloads\updater.exe",
            Version = new VersionMetadata { OriginalFilename = "powershell.exe" },
        });
        Assert.Contains(result.Findings, f => f.Contains("was compiled"));
    }

    [Fact]
    public void Hash_divergence_without_update_flagged_and_update_excuses()
    {
        var input = new MasqueradingInput
        {
            ImagePath = @"C:\Program Files\Tool\tool.exe",
            PreviousHashForPath = "AAAA",
            CurrentHash = "BBBB",
        };
        Assert.Contains(Analyzer.Analyze(input).Findings, f => f.Contains("changed content"));
        Assert.DoesNotContain(Analyzer.Analyze(input with { HashChangeExplainedByUpdate = true }).Findings,
            f => f.Contains("changed content"));
    }

    [Fact]
    public void Forged_parent_flagged()
    {
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = @"C:\Temp\x.exe",
            ParentForged = true,
        });
        Assert.Contains(result.Findings, f => f.Contains("spoofing"));
    }

    [Fact]
    public void Rlo_character_flagged()
    {
        var result = Analyzer.Analyze(new MasqueradingInput
        {
            ImagePath = "C:\\Temp\\fatura‮fdp.exe",
            Indicators = new StaticIndicators { HasRloCharacter = true },
        });
        Assert.Contains(result.Findings, f => f.Contains("RLO"));
    }

    [Theory]
    [InlineData("kitten", "sitting", 3)]
    [InlineData("svchost", "svchost", 0)]
    [InlineData("svchost", "svchots", 1)] // transposição (Damerau)
    public void Damerau_levenshtein_is_correct(string a, string b, int expected) =>
        Assert.Equal(expected, MasqueradingAnalyzer.DamerauLevenshtein(a, b));
}
