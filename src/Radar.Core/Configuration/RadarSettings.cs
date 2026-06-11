using System.Text.Json;
using System.Text.Json.Serialization;
using Radar.Core.Analysis;
using Radar.Core.Model;

namespace Radar.Core.Configuration;

/// <summary>Perfis de coleta. Pré-configuram os interruptores.</summary>
public enum CollectionProfile
{
    Complete = 0,
    Balanced = 1,
    Minimal = 2,
    Custom = 3,
}

/// <summary>Exclusão de coleta: o que for excluído NÃO é sequer gravado.</summary>
public sealed record CollectionExclusion
{
    public string? PathPrefix { get; init; }
    public string? SignerSubject { get; init; }
    public string? ProcessName { get; init; }
    public string? Note { get; init; }

    public bool Matches(string? imagePath, string? signerSubject)
    {
        if (PathPrefix is { } p && imagePath?.StartsWith(p, StringComparison.OrdinalIgnoreCase) == true) return true;
        if (SignerSubject is { } s && signerSubject?.Contains(s, StringComparison.OrdinalIgnoreCase) == true) return true;
        if (ProcessName is { } n && imagePath is not null &&
            Path.GetFileName(imagePath).Equals(n, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}

/// <summary>Intervalos das ações periódicas, ajustáveis com limites de proteção.</summary>
public sealed class PeriodicRates
{
    public int PersistenceScanMinutes { get; set; } = 15;          // [5, 1440]
    public int SignatureQueueBatchSeconds { get; set; } = 60;      // [10, 3600]
    public int RetentionPurgeHours { get; set; } = 24;             // [1, 168]
    public int BaselineRecomputeHours { get; set; } = 24;          // [1, 168]
    public int CuratedListUpdateDays { get; set; } = 7;            // [1, 90] (somente se opt-in online)
    public int AutoSnapshotDays { get; set; } = 7;                 // [1, 90]
    public int NotificationSummaryDays { get; set; } = 1;          // [1, 7]
    public int DbCheckpointSeconds { get; set; } = 30;             // [5, 600]
    /// <summary>Limite de vazão para ações orientadas a evento (hash de drop, verificação de binário novo).</summary>
    public int MaxHashOperationsPerMinute { get; set; } = 120;
    public int MaxSignatureVerificationsPerBatch { get; set; } = 50;
    /// <summary>Máximo de notificações por hora.</summary>
    public int MaxNotificationsPerHour { get; set; } = 6;

    public void Clamp()
    {
        PersistenceScanMinutes = Math.Clamp(PersistenceScanMinutes, 5, 1440);
        SignatureQueueBatchSeconds = Math.Clamp(SignatureQueueBatchSeconds, 10, 3600);
        RetentionPurgeHours = Math.Clamp(RetentionPurgeHours, 1, 168);
        BaselineRecomputeHours = Math.Clamp(BaselineRecomputeHours, 1, 168);
        CuratedListUpdateDays = Math.Clamp(CuratedListUpdateDays, 1, 90);
        AutoSnapshotDays = Math.Clamp(AutoSnapshotDays, 1, 90);
        NotificationSummaryDays = Math.Clamp(NotificationSummaryDays, 1, 7);
        DbCheckpointSeconds = Math.Clamp(DbCheckpointSeconds, 5, 600);
        MaxHashOperationsPerMinute = Math.Clamp(MaxHashOperationsPerMinute, 10, 1000);
        MaxSignatureVerificationsPerBatch = Math.Clamp(MaxSignatureVerificationsPerBatch, 5, 500);
        MaxNotificationsPerHour = Math.Clamp(MaxNotificationsPerHour, 1, 60);
    }
}

/// <summary>Notificações: sem notificação por padrão abaixo de Crítico.</summary>
public sealed class NotificationSettings
{
    public bool ToastEnabled { get; set; } = true;
    public ScoreBand MinimumBand { get; set; } = ScoreBand.Critical;
    public bool PeriodicSummaryEnabled { get; set; }
    public bool TrayBadgeForCritical { get; set; } = true;
}

/// <summary>Retenção: por tempo e por tamanho, com sumarização do que expira.</summary>
public sealed class RetentionSettings
{
    public int RawEventDays { get; set; } = 30;
    public int MaxDatabaseMegabytes { get; set; } = 2048;
}

/// <summary>
/// Configurações da aplicação. Persistidas como JSON na raiz de dados.
/// </summary>
public sealed class RadarSettings
{
    public const string DefaultDataRootLeaf = "fradar";

    /// <summary>Raiz única de dados. Padrão %LOCALAPPDATA%\fradar.</summary>
    public string DataRoot { get; set; } = DefaultDataRoot();

    public CollectionProfile Profile { get; set; } = CollectionProfile.Balanced;

    /// <summary>Interruptor independente por módulo de coleta.</summary>
    public Dictionary<CollectionModule, bool> Modules { get; set; } = DefaultsFor(CollectionProfile.Balanced);

    public List<CollectionExclusion> Exclusions { get; set; } = [];
    public PeriodicRates Rates { get; set; } = new();
    public NotificationSettings Notifications { get; set; } = new();
    public RetentionSettings Retention { get; set; } = new();

    /// <summary>"Encerrar a coleta ao fechar a interface". Padrão: desligado.</summary>
    public bool StopCollectorOnUiClose { get; set; }
    public bool StartCollectorWithWindows { get; set; }

    /// <summary>"Vida curta" configurável. Padrão 30s.</summary>
    public int ShortLivedThresholdSeconds { get; set; } = 30;
    public VisibilityMode VisibilityMode { get; set; } = VisibilityMode.Focus;
    public int QuarantineScoreThreshold { get; set; } = 50;

    /// <summary>Pesos do score, calibráveis.</summary>
    public ScoreWeights ScoreWeights { get; set; } = new();

    /// <summary>Zero telemetria por padrão; consultas externas opt-in granulares.</summary>
    public bool OptInOnlineListUpdates { get; set; }
    public bool OptInHashReputation { get; set; }
    public string? HashReputationApiKey { get; set; }

    /// <summary>PT-BR e EN no mínimo.</summary>
    public string Language { get; set; } = "pt-BR";

    /// <summary>Período de aprendizado do baseline.</summary>
    public int BaselineLearningDays { get; set; } = 7;

    /// <summary>Nível de log operacional.</summary>
    public string LogLevel { get; set; } = "Information";

    /// <summary>Assistente de primeiro uso já apresentado.</summary>
    public bool FirstRunCompleted { get; set; }

    public string DatabasePath => Path.Combine(DataRoot, "radar.db");
    public string LogsDirectory => Path.Combine(DataRoot, "logs");
    public string CuratedListsPath => Path.Combine(DataRoot, "lists", "curated.json");
    public string ReportsDirectory => Path.Combine(DataRoot, "reports");
    public string SettingsPath => Path.Combine(DataRoot, "settings.json");

    public static string DefaultDataRoot() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), DefaultDataRootLeaf);

    /// <summary>O perfil apenas pré-configura os interruptores.</summary>
    public static Dictionary<CollectionModule, bool> DefaultsFor(CollectionProfile profile) => profile switch
    {
        CollectionProfile.Complete => AllModules(true),
        CollectionProfile.Minimal => new Dictionary<CollectionModule, bool>(AllModules(false))
        {
            [CollectionModule.Processes] = true,
        },
        _ => new Dictionary<CollectionModule, bool>(AllModules(true))
        {
            [CollectionModule.ImageLoad] = false,
            [CollectionModule.FileSelfDelete] = true,
        },
    };

    private static Dictionary<CollectionModule, bool> AllModules(bool value) =>
        Enum.GetValues<CollectionModule>().ToDictionary(m => m, _ => value);

    public bool IsModuleEnabled(CollectionModule module) => Modules.GetValueOrDefault(module, false);

    /// <summary>Descrição em linguagem simples do que se perde ao desligar cada módulo.</summary>
    public static string WhatYouLose(CollectionModule module) => module switch
    {
        CollectionModule.Processes =>
            "É a fundação do produto: sem criação/término de processos, praticamente todas as features ficam suspensas.",
        CollectionModule.Network =>
            "Desativa o replay de comunicação, os sinais de exfiltração e o grafo de rede.",
        CollectionModule.Dns =>
            "Sem consultas DNS, conexões não são ligadas a domínios e a marcação de \"IP direto\" perde sentido.",
        CollectionModule.FileSensitiveReads =>
            "Perde o sinal mais forte de info-stealer: leitura de cofres de credenciais, carteiras e tokens.",
        CollectionModule.FileDrops =>
            "Perde a linhagem de arquivos: quem criou qual executável e o que ele virou quando rodou.",
        CollectionModule.FileSelfDelete =>
            "Perde a detecção de anti-forense (binários que se apagam após executar).",
        CollectionModule.ImageLoad =>
            "Perde a detecção de DLL não assinada carregada em processo confiável (sideloading).",
        CollectionModule.PersistenceScan =>
            "Sem varredura de autoruns, novas persistências não são detectadas nem correlacionadas.",
        CollectionModule.Baseline =>
            "Sem baseline, os atributos de novidade (\"nunca visto antes\") e prevalência param de funcionar.",
        _ => string.Empty,
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static RadarSettings LoadOrDefault(string? settingsPath = null)
    {
        var path = settingsPath ?? Path.Combine(DefaultDataRoot(), "settings.json");
        try
        {
            if (File.Exists(path))
            {
                var loaded = JsonSerializer.Deserialize<RadarSettings>(File.ReadAllText(path), JsonOptions);
                if (loaded is not null)
                {
                    loaded.Rates.Clamp();
                    return loaded;
                }
            }
        }
        catch
        {
            // arquivo corrompido → padrões (o log operacional registra no chamador)
        }
        return new RadarSettings();
    }

    public void Save()
    {
        Rates.Clamp();
        Directory.CreateDirectory(DataRoot);
        File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, JsonOptions));
    }
}
