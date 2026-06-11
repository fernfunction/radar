using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Radar.Core.Model;

namespace Radar.Collector;

/// <summary>
/// Captura ETW: Kernel Process (criador real, base do anti-spoofing), Kernel TCP/UDP
/// (tráfego atribuível a processos já mortos), DNS Client, Image Load e Kernel File seletivo.
/// Requer elevação; sem ela degrada para um observador por polling e avisa o que se perde.
/// Backpressure: file e image load; rede nunca.
/// </summary>
public sealed class EtwCollector : IDisposable
{
    private readonly CollectorContext _ctx;
    private readonly EnrichmentPipeline _pipeline;
    private TraceEventSession? _kernelSession;
    private TraceEventSession? _dnsSession;
    private Thread? _kernelThread;
    private Thread? _dnsThread;
    private System.Threading.Timer? _pollingFallback;
    private HashSet<int> _knownPids = [];
    private readonly int _ownPid = Environment.ProcessId;

    public bool KernelSessionActive { get; private set; }

    public EtwCollector(CollectorContext ctx, EnrichmentPipeline pipeline)
    {
        _ctx = ctx;
        _pipeline = pipeline;
    }

    public void Start()
    {
        if (_ctx.Elevated && TryStartKernelSession())
        {
            KernelSessionActive = true;
            TryStartDnsSession();
            _ctx.Log.Information("ETW sessions active (kernel + DNS). Full collection.");
        }
        else
        {
            _ctx.Log.Warning(
                "NO ELEVATION or ETW session failure: degrading to a polling observer. " +
                "Lost: processes living < ~2s, command lines of other users' processes, " +
                "per-process network, DNS, image load and file I/O. Run as administrator for full collection.");
            _ctx.LastError = "Degraded collection (no ETW). Run elevated for full capture.";
            StartPollingFallback();
        }
    }

    private bool TryStartKernelSession()
    {
        try
        {
            _kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName)
            {
                BufferSizeMB = 128,
            };
            _kernelSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO);

            var kernel = _kernelSession.Source.Kernel;

            kernel.ProcessStart += OnProcessStart;
            kernel.ProcessStop += OnProcessStop;

            kernel.TcpIpConnect += d => OnTcpConnect(d.ProcessID, d.daddr.ToString(), d.dport, d.TimeStamp);
            kernel.TcpIpConnectIPV6 += d => OnTcpConnect(d.ProcessID, d.daddr.ToString(), d.dport, d.TimeStamp);
            kernel.TcpIpSend += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Tcp, d.size, sent: true, d.TimeStamp);
            kernel.TcpIpSendIPV6 += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Tcp, d.size, sent: true, d.TimeStamp);
            kernel.TcpIpRecv += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Tcp, d.size, sent: false, d.TimeStamp);
            kernel.TcpIpRecvIPV6 += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Tcp, d.size, sent: false, d.TimeStamp);
            kernel.UdpIpSend += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Udp, d.size, sent: true, d.TimeStamp);
            kernel.UdpIpSendIPV6 += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Udp, d.size, sent: true, d.TimeStamp);
            kernel.UdpIpRecv += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Udp, d.size, sent: false, d.TimeStamp);
            kernel.UdpIpRecvIPV6 += d => OnNetBytes(d.ProcessID, d.daddr.ToString(), d.dport, NetworkProtocol.Udp, d.size, sent: false, d.TimeStamp);

            kernel.ImageLoad += OnImageLoad;

            kernel.FileIORead += d => OnFileRead(d.ProcessID, d.FileName, d.TimeStamp);
            kernel.FileIOCreate += d => OnFileCreate(d.ProcessID, d.FileName, d.TimeStamp);

            _kernelThread = new Thread(() =>
            {
                try { _kernelSession.Source.Process(); }
                catch (Exception ex) when (!_ctx.StopRequested)
                {
                    _ctx.LastError = $"Kernel ETW session went down: {ex.Message}";
                    _ctx.Log.Error(ex, "Kernel ETW session ended unexpectedly");
                }
            }) { IsBackground = true, Name = "radar-etw-kernel" };
            _kernelThread.Start();
            return true;
        }
        catch (Exception ex)
        {
            _ctx.Log.Error(ex, "Could not start the kernel ETW session");
            _kernelSession?.Dispose();
            _kernelSession = null;
            return false;
        }
    }

    private void TryStartDnsSession()
    {
        try
        {
            _dnsSession = new TraceEventSession("RadarDnsClientSession");
            _dnsSession.EnableProvider("Microsoft-Windows-DNS-Client", TraceEventLevel.Informational);
            _dnsSession.Source.Dynamic.All += OnDnsEvent;
            _dnsThread = new Thread(() =>
            {
                try { _dnsSession.Source.Process(); }
                catch (Exception ex) when (!_ctx.StopRequested)
                {
                    _ctx.Log.Error(ex, "DNS ETW session ended unexpectedly");
                }
            }) { IsBackground = true, Name = "radar-etw-dns" };
            _dnsThread.Start();
        }
        catch (Exception ex)
        {
            _ctx.Log.Warning(ex, "DNS-Client session unavailable - connections will have no associated domain");
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        _ctx.CountEvent();
        if (data.ProcessID == _ownPid) return;
        try
        {
            var imagePath = ResolveImagePath(data);
            _pipeline.OnProcessStart(data.ProcessID, imagePath, data.CommandLine, data.ParentID,
                new DateTimeOffset(data.TimeStamp.ToUniversalTime()));
        }
        catch (Exception ex)
        {
            _ctx.Log.Debug(ex, "ProcessStart failed");
        }
    }

    /// <summary>
    /// Resolve o caminho completo da imagem. Processos de vida curta já morreram quando
    /// consultados, então combinamos várias fontes: handle vivo, caminho NT do kernel, e, crucial
    /// para efêmeros, o caminho embutido na linha de comando. Sem isso, hash/assinatura/masquerading
    /// ficariam cegos justamente para o alvo principal do produto.
    /// </summary>
    private static string ResolveImagePath(ProcessTraceData data)
    {
        if (Windows.ProcessInspector.GetImagePath(data.ProcessID) is { Length: > 0 } live && IsRooted(live))
            return live;
        if (ConvertNtPath(StripNtPrefix(data.KernelImageFileName)) is { } fromKernel && IsRooted(fromKernel))
            return fromKernel;
        if (ExtractImageFromCommandLine(data.CommandLine) is { } fromCmd && IsRooted(fromCmd))
            return fromCmd;
        var kernelStripped = StripNtPrefix(data.KernelImageFileName);
        return IsRooted(kernelStripped) ? kernelStripped : data.ImageFileName;
    }

    private static bool IsRooted(string path) => path.Length > 2 && path[1] == ':';

    /// <summary>Remove o prefixo de objeto NT (\??\ ou \\?\) presente em algumas linhas de comando do kernel.</summary>
    private static string StripNtPrefix(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) return path[4..];
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path[4..];
        return path;
    }

    /// <summary>Extrai o caminho do executável da linha de comando ("C:\x\a.exe" args → C:\x\a.exe).</summary>
    private static string? ExtractImageFromCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var cl = StripNtPrefix(commandLine.Trim());
        if (cl.StartsWith('"'))
        {
            var end = cl.IndexOf('"', 1);
            return end > 1 ? cl[1..end] : null;
        }
        var exeIdx = cl.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0) return cl[..(exeIdx + 4)];
        var firstSpace = cl.IndexOf(' ');
        return firstSpace > 0 ? cl[..firstSpace] : cl;
    }

    private void OnProcessStop(ProcessTraceData data)
    {
        _ctx.CountEvent();
        try
        {
            _pipeline.OnProcessStop(data.ProcessID, data.ExitStatus,
                new DateTimeOffset(data.TimeStamp.ToUniversalTime()));
        }
        catch (Exception ex)
        {
            _ctx.Log.Debug(ex, "ProcessStop failed");
        }
    }

    private void OnTcpConnect(int pid, string address, int port, DateTime timestamp)
    {
        _ctx.CountEvent();
        if (!_ctx.ModuleOn(CollectionModule.Network) || pid == _ownPid) return;
        RecordConnection(pid, address, port, NetworkProtocol.Tcp, 0, 0, timestamp);
    }

    private void OnNetBytes(int pid, string address, int port, NetworkProtocol proto, int size, bool sent,
        DateTime timestamp)
    {
        _ctx.CountEvent();
        if (!_ctx.ModuleOn(CollectionModule.Network) || pid == _ownPid) return;
        RecordConnection(pid, address, port, proto, sent ? size : 0, sent ? 0 : size, timestamp);
    }

    private void RecordConnection(int pid, string address, int port, NetworkProtocol proto,
        long sentBytes, long recvBytes, DateTime timestamp)
    {
        var tracker = _ctx.FindTracker(pid);
        if (tracker is null) return;
        var when = new DateTimeOffset(timestamp.ToUniversalTime());

        var key = (address, port, proto);
        bool isNew = false;
        lock (tracker.Connections)
        {
            if (!tracker.Connections.TryGetValue(key, out var agg))
            {
                agg = new ExecutionTracker.ConnAgg { FirstSeenUtc = when, LastSeenUtc = when };
                agg.Domain = _ctx.IpToDomain.GetValueOrDefault(address);
                tracker.Connections[key] = agg;
                isNew = true;
            }
            agg.LastSeenUtc = when;
            agg.BytesSent += sentBytes;
            agg.BytesReceived += recvBytes;
        }
        Interlocked.Add(ref tracker.UploadBytes, sentBytes);
        Interlocked.Add(ref tracker.DownloadBytes, recvBytes);
        tracker.Dirty = true;

        if (isNew)
        {
            var domain = _ctx.IpToDomain.GetValueOrDefault(address);
            if (domain is null && !IsPrivateOrLocal(address))
            {
                // IP direto sem DNS prévio
                tracker.ConnectedDirectIp = true;
                tracker.NetworkEvidence.Add($"{address}:{port} with no prior DNS lookup");
            }
            if (domain is not null && IsDeadDrop(domain))
            {
                tracker.ContactedDeadDrop = true;
                tracker.NetworkEvidence.Add($"{domain} (frequently abused destination)");
            }

            if (!tracker.FirstConnectionLogged && !IsPrivateOrLocal(address))
            {
                tracker.FirstConnectionLogged = true;
                _ctx.Store.AddTimelineEvent(new TimelineEvent
                {
                    TimestampUtc = when,
                    Kind = TimelineEventKind.FirstNetworkConnection,
                    ExecutionId = tracker.ExecutionId,
                    Title = $"First external connection: {tracker.Execution.Binary.FileName}",
                    Detail = domain is null ? $"{address}:{port}" : $"{domain} ({address}:{port})",
                    Score = tracker.Execution.Score?.Total ?? 0,
                });
            }
        }
    }

    private void OnDnsEvent(TraceEvent evt)
    {
        _ctx.CountEvent();
        if ((int)evt.ID != 3008) return; // consulta concluída
        if (!_ctx.ModuleOn(CollectionModule.Dns) || evt.ProcessID == _ownPid) return;
        try
        {
            var domain = evt.PayloadByName("QueryName")?.ToString();
            if (string.IsNullOrWhiteSpace(domain)) return;
            var results = evt.PayloadByName("QueryResults")?.ToString() ?? string.Empty;

            var addresses = new List<string>();
            foreach (var token in results.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var value = token.Contains(' ') ? token[(token.LastIndexOf(' ') + 1)..] : token;
                if (IPAddress.TryParse(value.Trim(), out var ip))
                {
                    var text = ip.ToString();
                    addresses.Add(text);
                    _ctx.IpToDomain[text] = domain; // associação DNS para conexão
                }
            }

            var tracker = _ctx.FindTracker(evt.ProcessID);
            if (tracker is not null)
            {
                tracker.Domains.Add(domain);
                if (IsDeadDrop(domain))
                {
                    tracker.ContactedDeadDrop = true;
                    tracker.NetworkEvidence.Add($"{domain} (frequently abused destination)");
                    tracker.Dirty = true;
                }
                _ctx.Store.AddDnsQuery(new DnsQuery
                {
                    ExecutionId = tracker.ExecutionId,
                    TimestampUtc = new DateTimeOffset(evt.TimeStamp.ToUniversalTime()),
                    Domain = domain,
                    ResolvedAddresses = addresses,
                });
                _ctx.BaselineState.KnownDomains.Add(domain);
            }
        }
        catch (Exception ex)
        {
            _ctx.Log.Debug(ex, "DNS event failed");
        }
    }

    private void OnImageLoad(ImageLoadTraceData data)
    {
        _ctx.CountEvent();
        if (_ctx.ImageLoadDegraded || !_ctx.ModuleOn(CollectionModule.ImageLoad)) return;
        if (data.ProcessID == _ownPid) return;
        try
        {
            var tracker = _ctx.FindTracker(data.ProcessID);
            if (tracker is null) return;
            var path = ConvertNtPath(data.FileName) ?? data.FileName;
            if (path.Length == 0 || !tracker.ModulesSeen.Add(path)) return;
            if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;

            // Só módulos dignos de nota: diretório gravável pelo usuário
            if (!Core.Filtering.VisibilityFilter.IsUserWritableDirectory(path)) return;

            var signature = _ctx.Signatures.Verify(path);
            var hostTrusted = tracker.Execution.Binary.Signature.Status == SignatureStatus.SignedTrusted;
            var unsigned = signature.Status is SignatureStatus.Unsigned or SignatureStatus.SelfSigned;

            _ctx.Store.AddModuleLoad(new ModuleLoad
            {
                ExecutionId = tracker.ExecutionId,
                TimestampUtc = new DateTimeOffset(data.TimeStamp.ToUniversalTime()),
                ModulePath = path,
                SignatureStatus = signature.Status,
                FromUserWritableDirectory = true,
                HostIsTrusted = hostTrusted,
            });

            if (unsigned && hostTrusted)
            {
                tracker.LoadedUnsignedModuleInTrustedProcess = true;
                tracker.ModuleEvidence.Add(path);
                tracker.Dirty = true;
            }
        }
        catch (Exception ex)
        {
            _ctx.Log.Debug(ex, "ImageLoad failed");
        }
    }

    private void OnFileRead(int pid, string fileName, DateTime timestamp)
    {
        _ctx.CountEvent();
        CheckBackpressure();
        if (_ctx.FileIoDegraded || !_ctx.ModuleOn(CollectionModule.FileSensitiveReads)) return;
        if (pid == _ownPid || string.IsNullOrEmpty(fileName)) return;

        try
        {
            var tracker = _ctx.FindTracker(pid);
            if (tracker is null) return;

            var lower = fileName.ToLowerInvariant();
            foreach (var (pattern, category) in _ctx.Lists.SensitivePathPatterns)
            {
                if (!lower.Contains(pattern.ToLowerInvariant())) continue;
                // O dono legítimo lendo os próprios dados não é sinal (chrome.exe lendo perfil do Chrome)
                if (IsLegitimateOwner(tracker.Execution.Binary.FileName, category)) return;
                if (!tracker.SensitiveCategoriesSeen.Add(category)) return;

                tracker.ReadCredentialDirectories = true;
                tracker.CredentialEvidence.Add($"{category}: {fileName}");
                tracker.Dirty = true;
                _ctx.Store.AddFileActivity(new FileActivity
                {
                    ExecutionId = tracker.ExecutionId,
                    TimestampUtc = new DateTimeOffset(timestamp.ToUniversalTime()),
                    Kind = FileEventKind.SensitiveRead,
                    Path = fileName,
                    SensitiveCategory = category,
                });
                _ctx.Store.AddTimelineEvent(new TimelineEvent
                {
                    TimestampUtc = new DateTimeOffset(timestamp.ToUniversalTime()),
                    Kind = TimelineEventKind.SensitiveRead,
                    ExecutionId = tracker.ExecutionId,
                    Title = $"Sensitive read by {tracker.Execution.Binary.FileName}",
                    Detail = category,
                    Score = tracker.Execution.Score?.Total ?? 0,
                });
                return;
            }
        }
        catch (Exception ex)
        {
            _ctx.Log.Debug(ex, "FileRead failed");
        }
    }

    private void OnFileCreate(int pid, string fileName, DateTime timestamp)
    {
        _ctx.CountEvent();
        CheckBackpressure();
        if (_ctx.FileIoDegraded || !_ctx.ModuleOn(CollectionModule.FileDrops)) return;
        if (pid == _ownPid || string.IsNullOrEmpty(fileName)) return;

        try
        {
            var ext = Path.GetExtension(fileName);
            if (!_ctx.Lists.DroppableExtensions.Contains(ext)) return;

            var tracker = _ctx.FindTracker(pid);
            if (tracker is null) return;
            var path = ConvertNtPath(fileName) ?? fileName;
            if (!tracker.DroppedPaths.Add(path)) return;

            // Linhagem: quem criou o quê, e o que virou quando executou
            _ctx.DroppedFileToCreator[path] = tracker.ExecutionId;
            tracker.DropEvidence.Add(path);
            tracker.Dirty = true;

            // Hash do drop em segundo plano com vazão limitada
            var when = new DateTimeOffset(timestamp.ToUniversalTime());
            Task.Delay(TimeSpan.FromSeconds(2)).ContinueWith(_ =>
            {
                string? sha = null;
                try { sha = Windows.FileMetadataReader.ComputeSha256(path); } catch { }
                _ctx.Store.AddFileActivity(new FileActivity
                {
                    ExecutionId = tracker.ExecutionId,
                    TimestampUtc = when,
                    Kind = FileEventKind.ExecutableDrop,
                    Path = path,
                    Sha256 = sha,
                });
                _ctx.Store.AddTimelineEvent(new TimelineEvent
                {
                    TimestampUtc = when,
                    Kind = TimelineEventKind.ExecutableDrop,
                    ExecutionId = tracker.ExecutionId,
                    Title = $"Executable created by {tracker.Execution.Binary.FileName}",
                    Detail = path,
                    Score = tracker.Execution.Score?.Total ?? 0,
                });
            });
        }
        catch (Exception ex)
        {
            _ctx.Log.Debug(ex, "FileCreate failed");
        }
    }

    private static bool IsLegitimateOwner(string processFileName, string sensitiveCategory)
    {
        var proc = Path.GetFileNameWithoutExtension(processFileName).ToLowerInvariant();
        var category = sensitiveCategory.ToLowerInvariant();
        return (category.Contains("chrome") && proc.Contains("chrome")) ||
               (category.Contains("edge") && proc.Contains("msedge")) ||
               (category.Contains("firefox") && proc.Contains("firefox")) ||
               (category.Contains("brave") && proc.Contains("brave")) ||
               (category.Contains("opera") && proc.Contains("opera")) ||
               (category.Contains("discord") && proc.Contains("discord")) ||
               (category.Contains("telegram") && proc.Contains("telegram")) ||
               (category.Contains("whatsapp") && proc.Contains("whatsapp")) ||
               (category.Contains("steam") && proc.Contains("steam")) ||
               (category.Contains("keepass") && proc.Contains("keepass")) ||
               (category.Contains("1password") && proc.Contains("1password")) ||
               (category.Contains("bitwarden") && proc.Contains("bitwarden")) ||
               (category.Contains("ssh") && proc is "ssh" or "ssh-agent" or "scp" or "sftp" or "git") ||
               (category.Contains("aws") && proc.Contains("aws")) ||
               (category.Contains("git") && proc.Contains("git"));
    }

    private bool IsDeadDrop(string domain) =>
        _ctx.Lists.DeadDropDomainPatterns.Any(p =>
            domain.Contains(p, StringComparison.OrdinalIgnoreCase) ||
            p.Contains('/') && domain.EndsWith(p[..p.IndexOf('/')], StringComparison.OrdinalIgnoreCase));

    private static bool IsPrivateOrLocal(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254) ||
                   bytes[0] == 0 || bytes[0] >= 224;
        }
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast;
    }

    /// <summary>Backpressure: degrada file primeiro, image load depois; rede nunca.</summary>
    private void CheckBackpressure()
    {
        var rate = _ctx.CurrentEventsPerSecond;
        if (!_ctx.FileIoDegraded && rate > 20_000)
        {
            _ctx.FileIoDegraded = true;
            _ctx.Log.Warning("Backpressure: file I/O suspended ({Rate:0}/s)", rate);
        }
        else if (_ctx.FileIoDegraded && !_ctx.ImageLoadDegraded && rate > 30_000)
        {
            _ctx.ImageLoadDegraded = true;
            _ctx.Log.Warning("Backpressure: image load suspended ({Rate:0}/s)", rate);
        }
    }

    /// <summary>Restauração quando o volume normaliza (chamado pela rotina periódica).</summary>
    public void RelaxBackpressure()
    {
        var rate = _ctx.CurrentEventsPerSecond;
        if (rate < 5_000 && (_ctx.FileIoDegraded || _ctx.ImageLoadDegraded))
        {
            _ctx.FileIoDegraded = false;
            _ctx.ImageLoadDegraded = false;
            _ctx.Log.Information("Backpressure released ({Rate:0}/s) - full collection restored", rate);
        }
    }

    private void StartPollingFallback()
    {
        _knownPids = System.Diagnostics.Process.GetProcesses().Select(p => p.Id).ToHashSet();
        _pollingFallback = new System.Threading.Timer(_ =>
        {
            try
            {
                var current = System.Diagnostics.Process.GetProcesses();
                var currentIds = new HashSet<int>(current.Length);
                var now = DateTimeOffset.UtcNow;
                foreach (var proc in current)
                {
                    currentIds.Add(proc.Id);
                    if (_knownPids.Contains(proc.Id)) { proc.Dispose(); continue; }
                    try
                    {
                        var path = Windows.ProcessInspector.GetImagePath(proc.Id);
                        if (path is null) continue;
                        var parent = Windows.ProcessInspector.GetDeclaredParentPid(proc.Id) ?? 0;
                        _pipeline.OnProcessStart(proc.Id, path, commandLine: null, parent, now);
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
                foreach (var gone in _knownPids.Where(p => !currentIds.Contains(p)))
                    _pipeline.OnProcessStop(gone, null, now);
                _knownPids = currentIds;
            }
            catch (Exception ex)
            {
                _ctx.Log.Debug(ex, "Process polling failed");
            }
        }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }

    // Conversão \Device\HarddiskVolumeN\... → C:\...
    private static readonly Lazy<Dictionary<string, string>> DeviceMap = new(() =>
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                var letter = drive.Name.TrimEnd('\\');
                var target = new char[512];
                var len = QueryDosDevice(letter, target, target.Length);
                if (len > 0)
                {
                    var device = new string(target, 0, Array.IndexOf(target, '\0'));
                    map[device] = letter;
                }
            }
            catch { }
        }
        return map;
    });

    public static string? ConvertNtPath(string? ntPath)
    {
        if (string.IsNullOrEmpty(ntPath)) return null;
        if (ntPath.Length > 1 && ntPath[1] == ':') return ntPath;
        foreach (var (device, letter) in DeviceMap.Value)
        {
            if (ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return letter + ntPath[device.Length..];
        }
        return null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int QueryDosDevice(string lpDeviceName, [Out] char[] lpTargetPath, int ucchMax);

    public void Dispose()
    {
        _pollingFallback?.Dispose();
        try { _kernelSession?.Dispose(); } catch { }
        try { _dnsSession?.Dispose(); } catch { }
    }
}
