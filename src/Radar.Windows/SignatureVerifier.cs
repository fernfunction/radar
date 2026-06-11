using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Radar.Core.Model;

namespace Radar.Windows;

/// <summary>
/// Verificação Authenticode via WinVerifyTrust, incluindo assinatura por catálogo. Muitos
/// binários da Microsoft não têm assinatura embutida. Cache por hash.
/// Produz a taxonomia completa de estados.
/// </summary>
public sealed class SignatureVerifier
{
    private readonly ConcurrentDictionary<string, SignatureInfo> _cacheByHash = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="sha256">Hash do arquivo, usado como chave de cache.</param>
    public SignatureInfo Verify(string filePath, string? sha256 = null)
    {
        if (sha256 is not null && _cacheByHash.TryGetValue(sha256, out var cached))
            return cached;

        var info = VerifyUncached(filePath);
        if (sha256 is not null)
            _cacheByHash[sha256] = info;
        return info;
    }

    private static SignatureInfo VerifyUncached(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return new SignatureInfo { Status = SignatureStatus.Unknown, Details = "File no longer exists at verification time (only the history is preserved)." };

            var hr = VerifyEmbedded(filePath, out var embeddedRan);
            if (hr == 0)
                return BuildFromCertificate(filePath, isCatalog: false, SignatureStatus.SignedTrusted, null);

            switch (hr)
            {
                case TRUST_E_BAD_DIGEST:
                    return BuildFromCertificate(filePath, false, SignatureStatus.SignedInvalid,
                        "The file hash does not match the signature - the binary was altered after it was signed.");
                case CERT_E_REVOKED:
                    return BuildFromCertificate(filePath, false, SignatureStatus.SignedRevoked,
                        "The signing certificate was revoked by the issuer.");
                case CERT_E_EXPIRED:
                    return BuildFromCertificate(filePath, false, SignatureStatus.SignedWithCaveats,
                        "Expired certificate with no valid timestamp.");
                case CERT_E_CHAINING or CERT_E_UNTRUSTEDTESTROOT or CERT_E_WRONG_USAGE:
                    return BuildFromCertificate(filePath, false, SignatureStatus.SignedWithCaveats,
                        $"Incomplete or inadequate certificate chain (0x{hr:X8}).");
                case CERT_E_UNTRUSTEDROOT:
                {
                    var info = BuildFromCertificate(filePath, false, SignatureStatus.SignedWithCaveats,
                        "The chain does not end in a trusted root.");
                    // Auto-assinado: sujeito == emissor (estado 5)
                    if (info.Subject is not null && string.Equals(info.Subject, info.Issuer, StringComparison.Ordinal))
                        return info with { Status = SignatureStatus.SelfSigned, Details = "Self-signed certificate." };
                    return info;
                }
                case CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE:
                    return BuildFromCertificate(filePath, false, SignatureStatus.SignedWithCaveats,
                        "Could not confirm revocation (offline check).");
                case TRUST_E_NOSIGNATURE:
                    break;
                default:
                    if (embeddedRan)
                        return BuildFromCertificate(filePath, false, SignatureStatus.SignedWithCaveats,
                            $"Verification failure (0x{hr:X8}).");
                    break;
            }

            if (VerifyByCatalog(filePath, out var catalogFile))
            {
                return BuildFromCertificate(catalogFile!, isCatalog: true, SignatureStatus.SignedTrusted,
                    $"Signed via Windows catalog ({Path.GetFileName(catalogFile)}).");
            }

            return new SignatureInfo { Status = SignatureStatus.Unsigned };
        }
        catch (Exception ex)
        {
            return new SignatureInfo { Status = SignatureStatus.Unknown, Details = $"Verification error: {ex.Message}" };
        }
    }

    private static SignatureInfo BuildFromCertificate(string signedFilePath, bool isCatalog,
        SignatureStatus status, string? details)
    {
        string? subject = null, issuer = null, thumbprint = null;
        DateTimeOffset? notBefore = null, notAfter = null;
        var chainSubjects = new List<string>();
        bool isMicrosoftRoot = false;

        try
        {
            // SYSLIB0057: X509CertificateLoader não tem equivalente para extrair o certificado
            // de um PE assinado; CreateFromSignedFile continua sendo o caminho suportado para isso.
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFilePath));
#pragma warning restore SYSLIB0057
            subject = GetCn(cert.Subject);
            issuer = GetCn(cert.Issuer);
            thumbprint = cert.Thumbprint;
            notBefore = cert.NotBefore;
            notAfter = cert.NotAfter;

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // revogação já avaliada pelo WinVerifyTrust
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            if (chain.Build(cert) || chain.ChainElements.Count > 0)
            {
                foreach (var element in chain.ChainElements)
                    chainSubjects.Add(GetCn(element.Certificate.Subject) ?? element.Certificate.Subject);
                var root = chain.ChainElements[^1].Certificate;
                isMicrosoftRoot = root.Subject.Contains("Microsoft Root", StringComparison.OrdinalIgnoreCase) ||
                                  root.Subject.Contains("Microsoft ECC Product Root", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch
        {
            // sem certificado extraível; mantém apenas o estado
        }

        return new SignatureInfo
        {
            Status = status,
            Subject = subject,
            Issuer = issuer,
            Thumbprint = thumbprint,
            NotBefore = notBefore,
            NotAfter = notAfter,
            Chain = chainSubjects,
            IsCatalogSigned = isCatalog,
            IsMicrosoftRoot = isMicrosoftRoot,
            Details = details,
        };
    }

    private static string? GetCn(string distinguishedName)
    {
        foreach (var part in distinguishedName.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmed[3..].Trim('"');
        }
        return distinguishedName.Length > 0 ? distinguishedName : null;
    }

    private static int VerifyEmbedded(string filePath, out bool ran)
    {
        ran = false;
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
        };
        var pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN,
            };
            var pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            try
            {
                Marshal.StructureToPtr(data, pData, false);
                var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                var result = WinVerifyTrust(IntPtr.Zero, ref actionId, pData);
                ran = true;

                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, pData, false);
                WinVerifyTrust(IntPtr.Zero, ref actionId, pData);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pFileInfo);
        }
    }

    private static bool VerifyByCatalog(string filePath, out string? catalogFile)
    {
        catalogFile = null;
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hCatInfo = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
            {
                if (!CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
                    return false;
            }

            using var stream = File.OpenRead(filePath);
            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, stream.SafeFileHandle.DangerousGetHandle(),
                ref hashSize, null, 0);
            if (hashSize == 0) return false;
            var hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, stream.SafeFileHandle.DangerousGetHandle(),
                    ref hashSize, hash, 0))
                return false;

            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return false;

            var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0)) return false;

            catalogFile = catInfo.wszCatalogFile;
            // A presença do hash no catálogo + catálogo assinado é a validação prática;
            // o certificado do catálogo é extraído pelo chamador.
            return File.Exists(catalogFile);
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hCatInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2_GUID =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = WINTRUST_ACTION_GENERIC_VERIFY_V2_GUID;

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_CHAIN = 0x40;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    private const int CERT_E_UNTRUSTEDTESTROOT = unchecked((int)0x800B010D);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    private const int CERT_E_WRONG_USAGE = unchecked((int)0x800B0110);
    private const int CRYPT_E_NO_REVOCATION_CHECK = unchecked((int)0x80092012);
    private const int CRYPT_E_REVOCATION_OFFLINE = unchecked((int)0x80092013);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile,
        ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash,
        uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
}
