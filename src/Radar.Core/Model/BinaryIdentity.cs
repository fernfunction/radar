namespace Radar.Core.Model;

/// <summary>Detalhe da verificação Authenticode/catálogo.</summary>
public sealed record SignatureInfo
{
    public SignatureStatus Status { get; init; } = SignatureStatus.Unknown;
    /// <summary>Sujeito do certificado folha (quem assinou).</summary>
    public string? Subject { get; init; }
    /// <summary>Emissor do certificado folha.</summary>
    public string? Issuer { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public DateTimeOffset? NotAfter { get; init; }
    /// <summary>Assinatura veio de catálogo do Windows e não embutida no PE.</summary>
    public bool IsCatalogSigned { get; init; }
    /// <summary>Cadeia termina em raiz Microsoft (usado na filtragem).</summary>
    public bool IsMicrosoftRoot { get; init; }
    public string? Thumbprint { get; init; }
    /// <summary>Cadeia (sujeitos), da folha à raiz.</summary>
    public IReadOnlyList<string> Chain { get; init; } = [];
    /// <summary>Explicação legível do estado (ressalvas, motivo de invalidez).</summary>
    public string? Details { get; init; }

    public static SignatureInfo Unverified { get; } = new();

    public bool IsHighlightMax => Status is SignatureStatus.SignedInvalid or SignatureStatus.SignedRevoked;
}

/// <summary>Mark of the Web: ADS Zone.Identifier.</summary>
public sealed record MarkOfTheWeb
{
    /// <summary>Zona (3 = Internet).</summary>
    public int ZoneId { get; init; }
    public string? ReferrerUrl { get; init; }
    public string? HostUrl { get; init; }
    public bool FromInternet => ZoneId >= 3;
}

/// <summary>Indicadores estáticos leves calculados sobre o arquivo/nome.</summary>
public sealed record StaticIndicators
{
    /// <summary>Entropia de Shannon do arquivo (8.0 máx). Alta sugere packing.</summary>
    public double? FileEntropy { get; init; }
    /// <summary>fatura.pdf.exe: extensão dupla com extensão "de documento" antes da executável.</summary>
    public bool HasDoubleExtension { get; init; }
    /// <summary>Caracteres Unicode de direção (RLO U+202E) no nome.</summary>
    public bool HasRloCharacter { get; init; }
    /// <summary>Nome de arquivo com aparência aleatória (alta entropia do nome).</summary>
    public bool HasRandomLookingName { get; init; }
    /// <summary>Ícone de documento (PDF/planilha) em um executável.</summary>
    public bool HasDocumentLikeIcon { get; init; }
}

/// <summary>Metadados de versão do PE, usados também no masquerading.</summary>
public sealed record VersionMetadata
{
    public string? CompanyName { get; init; }
    public string? ProductName { get; init; }
    public string? OriginalFilename { get; init; }
    public string? FileDescription { get; init; }
    public string? FileVersion { get; init; }
}

/// <summary>Identidade do binário por trás de uma execução.</summary>
public sealed record BinaryIdentity
{
    public required string Path { get; init; }
    public string FileName => System.IO.Path.GetFileName(Path);
    public long SizeBytes { get; init; }
    public DateTimeOffset? FileCreatedUtc { get; init; }
    public DateTimeOffset? FileModifiedUtc { get; init; }
    /// <summary>Primeira vez que o monitor viu este binário (hash) nesta máquina.</summary>
    public DateTimeOffset? FirstSeenUtc { get; init; }
    public string? Sha256 { get; init; }
    /// <summary>Hash de import opcional para correlação futura.</summary>
    public string? ImportHash { get; init; }
    public VersionMetadata Version { get; init; } = new();
    public MarkOfTheWeb? Motw { get; init; }
    public StaticIndicators Indicators { get; init; } = new();
    public SignatureInfo Signature { get; init; } = SignatureInfo.Unverified;
}
