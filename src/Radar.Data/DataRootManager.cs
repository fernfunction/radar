using System.Diagnostics;
using Radar.Core.Configuration;

namespace Radar.Data;

public sealed record DataRootValidation
{
    public bool Ok => Errors.Count == 0;
    public IReadOnlyList<string> Errors { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed record MigrationResult(bool Success, int FilesMoved, string? Error);

/// <summary>
/// Gerência da raiz única de dados: validação prévia (escrita, espaço, caminho de
/// rede/removível), assistente de migração sem perda de histórico, e ACLs restritas. O banco de
/// evidências é alvo valioso para um atacante interessado em apagar rastros.
/// O ponteiro para uma raiz não-padrão vive em %LOCALAPPDATA%\fradar\root.pointer.
/// </summary>
public static class DataRootManager
{
    private static string PointerPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            RadarSettings.DefaultDataRootLeaf, "root.pointer");

    /// <summary>Resolve a raiz de dados atual: ponteiro (se houver) ou padrão.</summary>
    public static string ResolveDataRoot()
    {
        try
        {
            if (File.Exists(PointerPath))
            {
                var pointed = File.ReadAllText(PointerPath).Trim();
                if (pointed.Length > 0 && Directory.Exists(pointed)) return pointed;
            }
        }
        catch { /* ponteiro ilegível → padrão */ }
        return RadarSettings.DefaultDataRoot();
    }

    public static DataRootValidation Validate(string candidateRoot)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        try
        {
            var full = Path.GetFullPath(candidateRoot);

            if (full.StartsWith(@"\\", StringComparison.Ordinal))
                warnings.Add("Network path: continuous collection may fail if the network drops, and ACLs do not protect as on a local disk.");

            var root = Path.GetPathRoot(full);
            if (root is not null)
            {
                try
                {
                    var drive = new DriveInfo(root);
                    if (drive.DriveType == DriveType.Removable)
                        warnings.Add("Removable media: removing the device interrupts the recording of evidence.");
                    if (drive.IsReady && drive.AvailableFreeSpace < 1024L * 1024 * 1024)
                        warnings.Add($"Low free space ({drive.AvailableFreeSpace / (1024 * 1024)} MB free) - the retention cap may be reached quickly.");
                }
                catch { /* drive não consultável (ex.: UNC) */ }
            }

            // Validação de escrita real
            Directory.CreateDirectory(full);
            var probe = Path.Combine(full, $".radar-probe-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "probe");
            File.Delete(probe);
        }
        catch (Exception ex)
        {
            errors.Add($"No write permission or invalid path: {ex.Message}");
        }

        return new DataRootValidation { Errors = errors, Warnings = warnings };
    }

    /// <summary>
    /// Assistente de migração: move os dados existentes para a nova raiz e atualiza a
    /// referência, sem perda de histórico. O chamador deve parar o coletor antes.
    /// </summary>
    public static MigrationResult Migrate(string currentRoot, string newRoot, Action<string>? progress = null)
    {
        try
        {
            var validation = Validate(newRoot);
            if (!validation.Ok)
                return new MigrationResult(false, 0, string.Join("; ", validation.Errors));

            var source = Path.GetFullPath(currentRoot);
            var target = Path.GetFullPath(newRoot);
            if (string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
                return new MigrationResult(true, 0, null);

            int moved = 0;
            if (Directory.Exists(source))
            {
                foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
                {
                    var relative = Path.GetRelativePath(source, file);
                    if (relative.Equals("root.pointer", StringComparison.OrdinalIgnoreCase)) continue;
                    var dest = Path.Combine(target, relative);
                    Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                    progress?.Invoke(relative);
                    File.Copy(file, dest, overwrite: true);
                    moved++;
                }
                // Só remove os originais depois de toda a cópia ter sucesso
                foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
                {
                    var relative = Path.GetRelativePath(source, file);
                    if (relative.Equals("root.pointer", StringComparison.OrdinalIgnoreCase)) continue;
                    try { File.Delete(file); } catch { /* mantém o original como sobra inofensiva */ }
                }
            }

            SaveRootPointer(target);
            ApplyRestrictiveAcls(target);
            return new MigrationResult(true, moved, null);
        }
        catch (Exception ex)
        {
            return new MigrationResult(false, 0, ex.Message);
        }
    }

    public static void SaveRootPointer(string root)
    {
        var dir = Path.GetDirectoryName(PointerPath)!;
        Directory.CreateDirectory(dir);
        if (string.Equals(Path.GetFullPath(root), RadarSettings.DefaultDataRoot(), StringComparison.OrdinalIgnoreCase))
        {
            try { File.Delete(PointerPath); } catch { }
        }
        else
        {
            File.WriteAllText(PointerPath, root);
        }
    }

    /// <summary>
    /// ACLs restritas: remove herança e concede acesso apenas a SYSTEM, Administradores
    /// e ao usuário atual. Falha silenciosa registrada pelo chamador (sem elevação pode não aplicar).
    /// </summary>
    public static bool ApplyRestrictiveAcls(string root)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            var user = $"{Environment.UserDomainName}\\{Environment.UserName}";
            var psi = new ProcessStartInfo
            {
                FileName = "icacls.exe",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            // *S-1-5-18 = SYSTEM, *S-1-5-32-544 = Administradores (SIDs independem de idioma)
            foreach (var args in new[]
            {
                $"\"{root}\" /inheritance:r /grant:r \"*S-1-5-18:(OI)(CI)F\" \"*S-1-5-32-544:(OI)(CI)F\" \"{user}:(OI)(CI)F\"",
            })
            {
                psi.Arguments = args;
                using var proc = Process.Start(psi);
                proc!.WaitForExit(15000);
                if (proc.ExitCode != 0) return false;
            }
            return true;
        }
        catch
        {
            return false;
        }
    }
}
