using System.Diagnostics;
using System.Security.Cryptography;
using Radar.Core.Analysis;
using Radar.Core.Catalog;
using Radar.Core.Model;

namespace Radar.Windows;

/// <summary>
/// Identidade do binário: hash SHA-256, metadados de versão, Mark of the Web
/// (ADS Zone.Identifier), indicadores estáticos (entropia, extensão dupla, RLO, nome aleatório).
/// </summary>
public static class FileMetadataReader
{
    /// <summary>Monta a identidade completa de um binário; tolerante a arquivo já removido por auto-deleção.</summary>
    public static BinaryIdentity Read(string filePath, DateTimeOffset? firstSeenUtc, CuratedLists? lists = null,
        bool computeEntropy = true)
    {
        long size = 0;
        DateTimeOffset? created = null, modified = null;
        string? sha256 = null;
        double? entropy = null;

        try
        {
            var fi = new FileInfo(filePath);
            if (fi.Exists)
            {
                size = fi.Length;
                created = fi.CreationTimeUtc;
                modified = fi.LastWriteTimeUtc;
                sha256 = ComputeSha256(filePath);
                if (computeEntropy && size > 0 && size <= 64 * 1024 * 1024)
                {
                    using var stream = File.OpenRead(filePath);
                    entropy = StaticIndicatorAnalyzer.ShannonEntropy(stream);
                }
            }
        }
        catch
        {
            // arquivo inacessível/sumido: o dossiê preserva o que conseguiu
        }

        var nameIndicators = StaticIndicatorAnalyzer.Analyze(filePath, content: null, lists);

        return new BinaryIdentity
        {
            Path = filePath,
            SizeBytes = size,
            FileCreatedUtc = created,
            FileModifiedUtc = modified,
            FirstSeenUtc = firstSeenUtc,
            Sha256 = sha256,
            Version = ReadVersionMetadata(filePath),
            Motw = ReadMarkOfTheWeb(filePath),
            Indicators = nameIndicators with { FileEntropy = entropy },
        };
    }

    public static string? ComputeSha256(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch
        {
            return null;
        }
    }

    public static VersionMetadata ReadVersionMetadata(string filePath)
    {
        try
        {
            var v = FileVersionInfo.GetVersionInfo(filePath);
            return new VersionMetadata
            {
                CompanyName = Clean(v.CompanyName),
                ProductName = Clean(v.ProductName),
                OriginalFilename = Clean(v.OriginalFilename),
                FileDescription = Clean(v.FileDescription),
                FileVersion = Clean(v.FileVersion),
            };
        }
        catch
        {
            return new VersionMetadata();
        }

        static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    }

    /// <summary>
    /// Mark of the Web: ADS <c>:Zone.Identifier</c>. Info-stealers recém-baixados quase
    /// sempre o carregam (ou foram extraídos de um arquivo que carregava).
    /// </summary>
    public static MarkOfTheWeb? ReadMarkOfTheWeb(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath + ":Zone.Identifier", FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            int zoneId = -1;
            string? referrer = null, host = null;
            while (reader.ReadLine() is { } line)
            {
                if (line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase) &&
                    int.TryParse(line.AsSpan(7), out var z)) zoneId = z;
                else if (line.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase)) referrer = line[12..];
                else if (line.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase)) host = line[8..];
            }
            return zoneId >= 0 ? new MarkOfTheWeb { ZoneId = zoneId, ReferrerUrl = referrer, HostUrl = host } : null;
        }
        catch
        {
            return null; // sem ADS = sem MOTW
        }
    }
}
