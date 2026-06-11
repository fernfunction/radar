using System.Text.Json;
using System.Text.Json.Serialization;

namespace Radar.Core.Catalog;

/// <summary>
/// Listas curadas: embarcadas com padrões sensatos e atualizáveis offline por arquivo
/// JSON na raiz de dados (ou online por opt-in). Nomes de sistema, LOLBins, diretórios sensíveis,
/// padrões de dead drop, efêmeros legítimos.
/// </summary>
public sealed class CuratedLists
{
    public int Version { get; init; } = 1;

    /// <summary>Nome de binário de sistema → diretórios legítimos esperados.</summary>
    public Dictionary<string, string[]> SystemBinaryExpectedDirs { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = [@"%windir%\system32", @"%windir%\syswow64"],
        ["explorer.exe"] = [@"%windir%"],
        ["dllhost.exe"] = [@"%windir%\system32", @"%windir%\syswow64"],
        ["lsass.exe"] = [@"%windir%\system32"],
        ["csrss.exe"] = [@"%windir%\system32"],
        ["services.exe"] = [@"%windir%\system32"],
        ["winlogon.exe"] = [@"%windir%\system32"],
        ["smss.exe"] = [@"%windir%\system32"],
        ["taskhostw.exe"] = [@"%windir%\system32"],
        ["spoolsv.exe"] = [@"%windir%\system32"],
        ["wininit.exe"] = [@"%windir%\system32"],
        ["conhost.exe"] = [@"%windir%\system32"],
        ["rundll32.exe"] = [@"%windir%\system32", @"%windir%\syswow64"],
        ["wmiprvse.exe"] = [@"%windir%\system32\wbem", @"%windir%\syswow64\wbem"],
        ["ctfmon.exe"] = [@"%windir%\system32"],
        ["sihost.exe"] = [@"%windir%\system32"],
        ["fontdrvhost.exe"] = [@"%windir%\system32"],
        ["runtimebroker.exe"] = [@"%windir%\system32"],
        ["searchindexer.exe"] = [@"%windir%\system32"],
    };

    /// <summary>Dicionário de nomes conhecidos para typosquatting (distância de edição + homoglyphs).</summary>
    public HashSet<string> WellKnownProcessNames { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "explorer.exe", "dllhost.exe", "lsass.exe", "csrss.exe", "services.exe",
        "winlogon.exe", "smss.exe", "taskhostw.exe", "spoolsv.exe", "conhost.exe", "rundll32.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe", "winword.exe", "excel.exe",
        "powershell.exe", "cmd.exe", "notepad.exe", "teams.exe", "steam.exe", "discord.exe",
        "onedrive.exe", "dropbox.exe", "code.exe", "wmiprvse.exe", "ctfmon.exe",
    };

    /// <summary>LOLBins que voltam ao radar quando em padrão anômalo.</summary>
    public HashSet<string> LolBins { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
        "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
        "regsvcs.exe", "msiexec.exe", "forfiles.exe", "wmic.exe", "cmstp.exe",
        "esentutl.exe", "expand.exe", "curl.exe", "ftp.exe",
    };

    /// <summary>Hosts de shell/script. Quando filhos de pai improvável, sinal forte.</summary>
    public HashSet<string> ShellAndScriptHosts { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
    };

    /// <summary>Processos que hospedam documentos/conteúdo externo: pais improváveis de shells.</summary>
    public HashSet<string> DocumentHostProcesses { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "acrord32.exe", "acrobat.exe", "foxitreader.exe", "sumatrapdf.exe",
        "thunderbird.exe", "teams.exe", "discord.exe", "telegram.exe", "whatsapp.exe",
    };

    /// <summary>
    /// Diretórios/arquivos sensíveis (leituras de info-stealer): caminho relativo ao
    /// perfil do usuário ou com variáveis de ambiente, com categoria legível.
    /// </summary>
    public Dictionary<string, string> SensitivePathPatterns { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        [@"appdata\local\google\chrome\user data"] = "Chrome profile/credential vault",
        [@"appdata\local\microsoft\edge\user data"] = "Edge profile/credential vault",
        [@"appdata\roaming\mozilla\firefox\profiles"] = "Firefox profile/credential vault",
        [@"appdata\local\bravesoftware"] = "Brave profile/credential vault",
        [@"appdata\roaming\opera software"] = "Opera profile/credential vault",
        [@"appdata\roaming\exodus"] = "Cryptocurrency wallet (Exodus)",
        [@"appdata\roaming\electrum"] = "Cryptocurrency wallet (Electrum)",
        [@"appdata\roaming\atomic"] = "Cryptocurrency wallet (Atomic)",
        [@"appdata\local\coinomi"] = "Cryptocurrency wallet (Coinomi)",
        [@"appdata\roaming\bitcoin"] = "Cryptocurrency wallet (Bitcoin Core)",
        [@"appdata\roaming\keepass"] = "Password manager (KeePass)",
        [@"appdata\local\1password"] = "Password manager (1Password)",
        [@"appdata\roaming\bitwarden"] = "Password manager (Bitwarden)",
        [@"appdata\roaming\discord\local storage"] = "Discord tokens",
        [@"appdata\roaming\telegram desktop\tdata"] = "Telegram session",
        [@"appdata\roaming\whatsapp"] = "WhatsApp session",
        [@"appdata\local\steam"] = "Steam session/tokens",
        [@"\.ssh"] = "SSH keys",
        [@"\.aws"] = "AWS credentials",
        [@"\.azure"] = "Azure credentials",
        [@"\.config\gcloud"] = "Google Cloud credentials",
        [@"\.gitconfig"] = "Git configuration",
        [@"\.kube"] = "Kubernetes credentials",
    };

    /// <summary>Padrões de domínio de "dead drop"/exfiltração frequentemente abusados.</summary>
    public List<string> DeadDropDomainPatterns { get; init; } =
    [
        "api.telegram.org",
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "rentry.co",
        "transfer.sh",
        "file.io",
        "anonfiles.com",
        "gofile.io",
        "catbox.moe",
        "0x0.st",
        "termbin.com",
        "webhook.site",
        "pipedream.net",
        "interactsh.com",
        "oastify.com",
        "burpcollaborator.net",
        "requestbin.net",
        "ngrok.io",
        "ngrok-free.app",
        "trycloudflare.com",
    ];

    /// <summary>Efêmeros legítimos e frequentes suprimíveis (por assinatura+caminho).</summary>
    public HashSet<string> KnownEphemeralProcesses { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "conhost.exe", "vctip.exe", "tracker.exe", "mspdbsrv.exe", "vbcscompiler.exe",
        "csc.exe", "cvtres.exe", "werfault.exe", "backgroundtaskhost.exe", "dllhost.exe",
        "taskhostw.exe", "gpupdate.exe", "wermgr.exe", "compattelrunner.exe",
    };

    /// <summary>Extensões de executável/script consideradas "drop" quando criadas.</summary>
    public HashSet<string> DroppableExtensions { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".ps1", ".js", ".vbs", ".bat", ".cmd", ".scr", ".hta", ".jse", ".vbe", ".wsf", ".msi", ".com", ".pif",
    };

    /// <summary>Extensões "de documento" usadas na detecção de extensão dupla (fatura.pdf.exe).</summary>
    public HashSet<string> DocumentExtensions { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".zip", ".rar", ".mp3", ".mp4",
    };

    /// <summary>Fabricantes cujo nome em metadados exige assinatura correspondente.</summary>
    public Dictionary<string, string[]> VendorNameToSignerHints { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["microsoft"] = ["microsoft"],
        ["google"] = ["google"],
        ["adobe"] = ["adobe"],
        ["mozilla"] = ["mozilla"],
        ["oracle"] = ["oracle"],
        ["nvidia"] = ["nvidia"],
        ["intel"] = ["intel"],
        ["valve"] = ["valve"],
        ["discord"] = ["discord"],
        ["dropbox"] = ["dropbox"],
    };

    public static CuratedLists Default { get; } = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Carrega listas de um arquivo JSON na raiz de dados; ausência/erro → padrões embarcados.</summary>
    public static CuratedLists LoadOrDefault(string? jsonFilePath)
    {
        if (jsonFilePath is null || !File.Exists(jsonFilePath)) return Default;
        try
        {
            var loaded = JsonSerializer.Deserialize<CuratedLists>(File.ReadAllText(jsonFilePath), JsonOptions);
            return loaded ?? Default;
        }
        catch
        {
            return Default;
        }
    }

    /// <summary>Exporta as listas atuais (para o usuário editar/atualizar offline).</summary>
    public void Save(string jsonFilePath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(jsonFilePath)!);
        File.WriteAllText(jsonFilePath, JsonSerializer.Serialize(this, JsonOptions));
    }
}
