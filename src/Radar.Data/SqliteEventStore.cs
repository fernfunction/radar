using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Radar.Core.Abstractions;
using Radar.Core.Analysis;
using Radar.Core.Filtering;
using Radar.Core.Model;

namespace Radar.Data;

/// <summary>
/// Banco histórico local: SQLite em WAL. O coletor escreve enquanto a UI lê de outro
/// processo. Documentos ricos (dossiê, score, ancestralidade) ficam em JSON; colunas indexadas
/// cobrem os filtros das vistas. Retenção por tempo+tamanho com sumarização.
/// </summary>
public sealed class SqliteEventStore : IEventStore, IDisposable
{
    private readonly string _dbPath;
    private readonly string _connectionString;
    private readonly bool _readOnly;
    private readonly object _writeLock = new();

    private static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public SqliteEventStore(string dbPath, bool readOnly = false)
    {
        _dbPath = dbPath;
        _readOnly = readOnly;
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = 15,
            Pooling = true,
        }.ToString();

        if (!readOnly) InitializeSchema();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout=15000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    private void InitializeSchema()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA auto_vacuum=INCREMENTAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS executions(
                execution_id TEXT PRIMARY KEY,
                created_utc INTEGER NOT NULL,
                exited_utc INTEGER,
                sha256 TEXT,
                image_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                user_name TEXT,
                score_total INTEGER NOT NULL DEFAULT 0,
                score_muted INTEGER NOT NULL DEFAULT 0,
                sig_status INTEGER NOT NULL DEFAULT 0,
                has_network INTEGER NOT NULL DEFAULT 0,
                parent_execution_id TEXT,
                json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_exec_created ON executions(created_utc);
            CREATE INDEX IF NOT EXISTS ix_exec_sha ON executions(sha256);
            CREATE INDEX IF NOT EXISTS ix_exec_path ON executions(image_path);
            CREATE INDEX IF NOT EXISTS ix_exec_score ON executions(score_total);
            CREATE INDEX IF NOT EXISTS ix_exec_parent ON executions(parent_execution_id);

            CREATE TABLE IF NOT EXISTS network_connections(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                first_seen_utc INTEGER NOT NULL,
                last_seen_utc INTEGER,
                protocol INTEGER NOT NULL,
                remote_addr TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                local_port INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                domain TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_net_exec ON network_connections(execution_id);
            CREATE INDEX IF NOT EXISTS ix_net_seen ON network_connections(first_seen_utc);
            CREATE INDEX IF NOT EXISTS ix_net_addr ON network_connections(remote_addr);

            CREATE TABLE IF NOT EXISTS dns_queries(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                ts_utc INTEGER NOT NULL,
                domain TEXT NOT NULL,
                addresses TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_dns_exec ON dns_queries(execution_id);
            CREATE INDEX IF NOT EXISTS ix_dns_domain ON dns_queries(domain);

            CREATE TABLE IF NOT EXISTS file_activities(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                ts_utc INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT,
                category TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_file_exec ON file_activities(execution_id);
            CREATE INDEX IF NOT EXISTS ix_file_sha ON file_activities(sha256);

            CREATE TABLE IF NOT EXISTS module_loads(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                ts_utc INTEGER NOT NULL,
                path TEXT NOT NULL,
                sig_status INTEGER NOT NULL DEFAULT 0,
                from_writable INTEGER NOT NULL DEFAULT 0,
                host_trusted INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_mod_exec ON module_loads(execution_id);

            CREATE TABLE IF NOT EXISTS resource_samples(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                ts_utc INTEGER NOT NULL,
                cpu REAL NOT NULL,
                working_set INTEGER NOT NULL,
                io_bps INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_res_exec ON resource_samples(execution_id);

            CREATE TABLE IF NOT EXISTS timeline_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                execution_id TEXT,
                title TEXT NOT NULL,
                detail TEXT,
                score INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_timeline_ts ON timeline_events(ts_utc);

            CREATE TABLE IF NOT EXISTS persistence_entries(
                id TEXT PRIMARY KEY,
                kind INTEGER NOT NULL,
                location TEXT NOT NULL,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                target_binary TEXT,
                first_seen_utc INTEGER NOT NULL,
                last_seen_utc INTEGER NOT NULL,
                removed_utc INTEGER,
                installer_execution_id TEXT,
                author TEXT,
                trigger_desc TEXT,
                sig_json TEXT
            );

            CREATE TABLE IF NOT EXISTS trust_list(
                sha256 TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                signer TEXT,
                added_utc INTEGER NOT NULL,
                note TEXT
            );

            CREATE TABLE IF NOT EXISTS baseline(
                id INTEGER PRIMARY KEY CHECK (id = 1),
                json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                taken_utc INTEGER NOT NULL,
                label TEXT,
                json TEXT NOT NULL
            );

            -- Eventos brutos antigos viram resumos estatísticos
            CREATE TABLE IF NOT EXISTS execution_summaries(
                binary_key TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                image_path TEXT NOT NULL,
                run_count INTEGER NOT NULL,
                first_utc INTEGER NOT NULL,
                last_utc INTEGER NOT NULL,
                max_score INTEGER NOT NULL,
                total_upload_bytes INTEGER NOT NULL DEFAULT 0
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public void UpsertExecution(ProcessExecution execution)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO executions(execution_id, created_utc, exited_utc, sha256, image_path, file_name,
                                       user_name, score_total, score_muted, sig_status, parent_execution_id, json)
                VALUES ($id, $created, $exited, $sha, $path, $name, $user, $score, $muted, $sig, $parent, $json)
                ON CONFLICT(execution_id) DO UPDATE SET
                    exited_utc=excluded.exited_utc, sha256=excluded.sha256, score_total=excluded.score_total,
                    score_muted=excluded.score_muted, sig_status=excluded.sig_status, json=excluded.json;
                """;
            cmd.Parameters.AddWithValue("$id", execution.ExecutionId.ToString("N"));
            cmd.Parameters.AddWithValue("$created", execution.CreatedUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$exited", (object?)execution.ExitedUtc?.ToUnixTimeMilliseconds() ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sha", (object?)execution.Binary.Sha256 ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$path", execution.Binary.Path);
            cmd.Parameters.AddWithValue("$name", execution.Binary.FileName);
            cmd.Parameters.AddWithValue("$user", (object?)execution.Security.UserName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$score", execution.Score?.Muted == true ? 0 : execution.Score?.Total ?? 0);
            cmd.Parameters.AddWithValue("$muted", execution.Score?.Muted == true ? 1 : 0);
            cmd.Parameters.AddWithValue("$sig", (int)execution.Binary.Signature.Status);
            cmd.Parameters.AddWithValue("$parent", (object?)execution.ParentExecutionId?.ToString("N") ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$json", JsonSerializer.Serialize(execution, Json));
            cmd.ExecuteNonQuery();
        }
    }

    public ProcessExecution? GetExecution(Guid executionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM executions WHERE execution_id=$id";
        cmd.Parameters.AddWithValue("$id", executionId.ToString("N"));
        return cmd.ExecuteScalar() is string json ? Deserialize(json) : null;
    }

    public IReadOnlyList<ProcessExecution> QueryExecutions(ExecutionQuery query)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (query.FromUtc is { } from)
        {
            where.Add("created_utc >= $from");
            cmd.Parameters.AddWithValue("$from", from.ToUnixTimeMilliseconds());
        }
        if (query.ToUtc is { } to)
        {
            where.Add("created_utc <= $to");
            cmd.Parameters.AddWithValue("$to", to.ToUnixTimeMilliseconds());
        }
        if (query.UserName is { } user)
        {
            where.Add("user_name = $user COLLATE NOCASE");
            cmd.Parameters.AddWithValue("$user", user);
        }
        if (query.MinScore is { } minScore)
        {
            where.Add("score_total >= $minScore");
            cmd.Parameters.AddWithValue("$minScore", minScore);
        }
        if (query.SignatureStatus is { } sig)
        {
            where.Add("sig_status = $sig");
            cmd.Parameters.AddWithValue("$sig", (int)sig);
        }
        if (query.HasNetworkActivity is { } hasNet)
            where.Add($"has_network = {(hasNet ? 1 : 0)}");
        if (query.PathPrefix is { } prefix)
        {
            where.Add("image_path LIKE $prefix || '%' COLLATE NOCASE");
            cmd.Parameters.AddWithValue("$prefix", prefix);
        }
        if (query.OnlyShortLived)
            where.Add("exited_utc IS NOT NULL");
        if (!string.IsNullOrWhiteSpace(query.SearchText))
        {
            // Busca por nome, caminho, hash, domínio, IP, emissor, usuário
            where.Add("""
                (file_name LIKE '%' || $search || '%' COLLATE NOCASE
                 OR image_path LIKE '%' || $search || '%' COLLATE NOCASE
                 OR sha256 LIKE '%' || $search || '%' COLLATE NOCASE
                 OR user_name LIKE '%' || $search || '%' COLLATE NOCASE
                 OR json LIKE '%' || $search || '%' COLLATE NOCASE
                 OR execution_id IN (SELECT execution_id FROM dns_queries WHERE domain LIKE '%' || $search || '%')
                 OR execution_id IN (SELECT execution_id FROM network_connections WHERE remote_addr LIKE '%' || $search || '%'))
                """);
            cmd.Parameters.AddWithValue("$search", query.SearchText);
        }

        cmd.CommandText = "SELECT json FROM executions" +
                          (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : string.Empty) +
                          " ORDER BY created_utc DESC LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", query.Limit);

        return ReadExecutions(cmd);
    }

    public IReadOnlyList<ProcessExecution> GetExecutionsForBinary(string sha256, int limit = 100)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM executions WHERE sha256=$sha ORDER BY created_utc DESC LIMIT $limit";
        cmd.Parameters.AddWithValue("$sha", sha256);
        cmd.Parameters.AddWithValue("$limit", limit);
        return ReadExecutions(cmd);
    }

    public IReadOnlyList<ProcessExecution> GetChildren(Guid executionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM executions WHERE parent_execution_id=$id ORDER BY created_utc";
        cmd.Parameters.AddWithValue("$id", executionId.ToString("N"));
        return ReadExecutions(cmd);
    }

    public int CountPriorRuns(string sha256, DateTimeOffset beforeUtc)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT (SELECT COUNT(*) FROM executions WHERE sha256=$sha AND created_utc < $before)
                 + COALESCE((SELECT run_count FROM execution_summaries WHERE binary_key=$sha), 0)
            """;
        cmd.Parameters.AddWithValue("$sha", sha256);
        cmd.Parameters.AddWithValue("$before", beforeUtc.ToUnixTimeMilliseconds());
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    public string? GetLastHashForPath(string path)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256 FROM executions WHERE image_path=$path COLLATE NOCASE AND sha256 IS NOT NULL ORDER BY created_utc DESC LIMIT 1";
        cmd.Parameters.AddWithValue("$path", path);
        return cmd.ExecuteScalar() as string;
    }

    private static List<ProcessExecution> ReadExecutions(SqliteCommand cmd)
    {
        var result = new List<ProcessExecution>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            if (Deserialize(reader.GetString(0)) is { } exec) result.Add(exec);
        }
        return result;
    }

    private static ProcessExecution? Deserialize(string json)
    {
        try { return JsonSerializer.Deserialize<ProcessExecution>(json, Json); }
        catch { return null; }
    }

    public void AddNetworkConnection(NetworkConnection c)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO network_connections(execution_id, first_seen_utc, last_seen_utc, protocol,
                    remote_addr, remote_port, local_port, bytes_sent, bytes_received, domain)
                VALUES ($exec, $first, $last, $proto, $addr, $rport, $lport, $sent, $recv, $domain);
                UPDATE executions SET has_network=1 WHERE execution_id=$exec;
                """;
            cmd.Parameters.AddWithValue("$exec", c.ExecutionId.ToString("N"));
            cmd.Parameters.AddWithValue("$first", c.FirstSeenUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$last", (object?)c.LastSeenUtc?.ToUnixTimeMilliseconds() ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$proto", (int)c.Protocol);
            cmd.Parameters.AddWithValue("$addr", c.RemoteAddress);
            cmd.Parameters.AddWithValue("$rport", c.RemotePort);
            cmd.Parameters.AddWithValue("$lport", c.LocalPort);
            cmd.Parameters.AddWithValue("$sent", c.BytesSent);
            cmd.Parameters.AddWithValue("$recv", c.BytesReceived);
            cmd.Parameters.AddWithValue("$domain", (object?)c.ResolvedFromDomain ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
    }

    public void AddDnsQuery(DnsQuery q)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO dns_queries(execution_id, ts_utc, domain, addresses) VALUES ($exec, $ts, $domain, $addrs)";
            cmd.Parameters.AddWithValue("$exec", q.ExecutionId.ToString("N"));
            cmd.Parameters.AddWithValue("$ts", q.TimestampUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$domain", q.Domain);
            cmd.Parameters.AddWithValue("$addrs", JsonSerializer.Serialize(q.ResolvedAddresses, Json));
            cmd.ExecuteNonQuery();
        }
    }

    public void AddFileActivity(FileActivity a)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO file_activities(execution_id, ts_utc, kind, path, sha256, category) VALUES ($exec, $ts, $kind, $path, $sha, $cat)";
            cmd.Parameters.AddWithValue("$exec", a.ExecutionId.ToString("N"));
            cmd.Parameters.AddWithValue("$ts", a.TimestampUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$kind", (int)a.Kind);
            cmd.Parameters.AddWithValue("$path", a.Path);
            cmd.Parameters.AddWithValue("$sha", (object?)a.Sha256 ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$cat", (object?)a.SensitiveCategory ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
    }

    public void AddModuleLoad(ModuleLoad m)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO module_loads(execution_id, ts_utc, path, sig_status, from_writable, host_trusted) VALUES ($exec, $ts, $path, $sig, $writable, $trusted)";
            cmd.Parameters.AddWithValue("$exec", m.ExecutionId.ToString("N"));
            cmd.Parameters.AddWithValue("$ts", m.TimestampUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$path", m.ModulePath);
            cmd.Parameters.AddWithValue("$sig", (int)m.SignatureStatus);
            cmd.Parameters.AddWithValue("$writable", m.FromUserWritableDirectory ? 1 : 0);
            cmd.Parameters.AddWithValue("$trusted", m.HostIsTrusted ? 1 : 0);
            cmd.ExecuteNonQuery();
        }
    }

    public void AddResourceSample(ResourceSample s)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO resource_samples(execution_id, ts_utc, cpu, working_set, io_bps) VALUES ($exec, $ts, $cpu, $ws, $io)";
            cmd.Parameters.AddWithValue("$exec", s.ExecutionId.ToString("N"));
            cmd.Parameters.AddWithValue("$ts", s.TimestampUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$cpu", s.CpuPercent);
            cmd.Parameters.AddWithValue("$ws", s.WorkingSetBytes);
            cmd.Parameters.AddWithValue("$io", s.IoBytesPerSecond);
            cmd.ExecuteNonQuery();
        }
    }

    public void AddSystemMarker(SystemMarker marker) => AddTimelineEvent(new TimelineEvent
    {
        TimestampUtc = marker.TimestampUtc,
        Kind = TimelineEventKind.SystemMarker,
        Title = marker.Kind switch
        {
            SystemMarkerKind.Logon => "User logon",
            SystemMarkerKind.Logoff => "User logoff",
            SystemMarkerKind.ResumeFromSleep => "Resume from sleep",
            SystemMarkerKind.NetworkChange => "Connected to a new network",
            SystemMarkerKind.CollectorStarted => "Collection started",
            SystemMarkerKind.CollectorStopped => "Collection stopped",
            SystemMarkerKind.CollectorPaused => "Collection paused",
            _ => marker.Kind.ToString(),
        },
        Detail = marker.Detail,
    });

    public void AddTimelineEvent(TimelineEvent evt)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO timeline_events(ts_utc, kind, execution_id, title, detail, score) VALUES ($ts, $kind, $exec, $title, $detail, $score)";
            cmd.Parameters.AddWithValue("$ts", evt.TimestampUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$kind", (int)evt.Kind);
            cmd.Parameters.AddWithValue("$exec", (object?)evt.ExecutionId?.ToString("N") ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$title", evt.Title);
            cmd.Parameters.AddWithValue("$detail", (object?)evt.Detail ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$score", evt.Score);
            cmd.ExecuteNonQuery();
        }
    }

    public IReadOnlyList<NetworkConnection> GetConnections(Guid executionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT first_seen_utc, last_seen_utc, protocol, remote_addr, remote_port, local_port, bytes_sent, bytes_received, domain FROM network_connections WHERE execution_id=$exec ORDER BY first_seen_utc";
        cmd.Parameters.AddWithValue("$exec", executionId.ToString("N"));
        var result = new List<NetworkConnection>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new NetworkConnection
            {
                ExecutionId = executionId,
                FirstSeenUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(0)),
                LastSeenUtc = reader.IsDBNull(1) ? null : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(1)),
                Protocol = (NetworkProtocol)reader.GetInt32(2),
                RemoteAddress = reader.GetString(3),
                RemotePort = reader.GetInt32(4),
                LocalPort = reader.GetInt32(5),
                BytesSent = reader.GetInt64(6),
                BytesReceived = reader.GetInt64(7),
                ResolvedFromDomain = reader.IsDBNull(8) ? null : reader.GetString(8),
            });
        }
        return result;
    }

    public IReadOnlyList<DnsQuery> GetDnsQueries(Guid executionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ts_utc, domain, addresses FROM dns_queries WHERE execution_id=$exec ORDER BY ts_utc";
        cmd.Parameters.AddWithValue("$exec", executionId.ToString("N"));
        var result = new List<DnsQuery>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new DnsQuery
            {
                ExecutionId = executionId,
                TimestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(0)),
                Domain = reader.GetString(1),
                ResolvedAddresses = reader.IsDBNull(2)
                    ? []
                    : JsonSerializer.Deserialize<string[]>(reader.GetString(2), Json) ?? [],
            });
        }
        return result;
    }

    public IReadOnlyList<FileActivity> GetFileActivities(Guid executionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ts_utc, kind, path, sha256, category FROM file_activities WHERE execution_id=$exec ORDER BY ts_utc";
        cmd.Parameters.AddWithValue("$exec", executionId.ToString("N"));
        var result = new List<FileActivity>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new FileActivity
            {
                ExecutionId = executionId,
                TimestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(0)),
                Kind = (FileEventKind)reader.GetInt32(1),
                Path = reader.GetString(2),
                Sha256 = reader.IsDBNull(3) ? null : reader.GetString(3),
                SensitiveCategory = reader.IsDBNull(4) ? null : reader.GetString(4),
            });
        }
        return result;
    }

    public IReadOnlyList<ModuleLoad> GetModuleLoads(Guid executionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ts_utc, path, sig_status, from_writable, host_trusted FROM module_loads WHERE execution_id=$exec ORDER BY ts_utc";
        cmd.Parameters.AddWithValue("$exec", executionId.ToString("N"));
        var result = new List<ModuleLoad>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new ModuleLoad
            {
                ExecutionId = executionId,
                TimestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(0)),
                ModulePath = reader.GetString(1),
                SignatureStatus = (SignatureStatus)reader.GetInt32(2),
                FromUserWritableDirectory = reader.GetInt32(3) == 1,
                HostIsTrusted = reader.GetInt32(4) == 1,
            });
        }
        return result;
    }

    public IReadOnlyList<ResourceSample> GetResourceSamples(Guid executionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ts_utc, cpu, working_set, io_bps FROM resource_samples WHERE execution_id=$exec ORDER BY ts_utc";
        cmd.Parameters.AddWithValue("$exec", executionId.ToString("N"));
        var result = new List<ResourceSample>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new ResourceSample
            {
                ExecutionId = executionId,
                TimestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(0)),
                CpuPercent = reader.GetDouble(1),
                WorkingSetBytes = reader.GetInt64(2),
                IoBytesPerSecond = reader.GetInt64(3),
            });
        }
        return result;
    }

    public IReadOnlyList<TimelineEvent> GetTimeline(DateTimeOffset fromUtc, DateTimeOffset toUtc, int minScore = 0)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT ts_utc, kind, execution_id, title, detail, score FROM timeline_events
            WHERE ts_utc BETWEEN $from AND $to AND (score >= $minScore OR kind = 6)
            ORDER BY ts_utc DESC LIMIT 5000
            """;
        cmd.Parameters.AddWithValue("$from", fromUtc.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$to", toUtc.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$minScore", minScore);
        var result = new List<TimelineEvent>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new TimelineEvent
            {
                TimestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(0)),
                Kind = (TimelineEventKind)reader.GetInt32(1),
                ExecutionId = reader.IsDBNull(2) ? null : Guid.ParseExact(reader.GetString(2), "N"),
                Title = reader.GetString(3),
                Detail = reader.IsDBNull(4) ? null : reader.GetString(4),
                Score = reader.GetInt32(5),
            });
        }
        return result;
    }

    public void UpsertPersistenceEntry(PersistenceEntry entry)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO persistence_entries(id, kind, location, name, target, target_binary,
                    first_seen_utc, last_seen_utc, removed_utc, installer_execution_id, author, trigger_desc, sig_json)
                VALUES ($id, $kind, $loc, $name, $target, $bin, $first, $last, $removed, $installer, $author, $trigger, $sig)
                ON CONFLICT(id) DO UPDATE SET
                    target=excluded.target, target_binary=excluded.target_binary, last_seen_utc=excluded.last_seen_utc,
                    removed_utc=excluded.removed_utc, sig_json=excluded.sig_json,
                    installer_execution_id=COALESCE(persistence_entries.installer_execution_id, excluded.installer_execution_id);
                """;
            cmd.Parameters.AddWithValue("$id", entry.Id);
            cmd.Parameters.AddWithValue("$kind", (int)entry.Kind);
            cmd.Parameters.AddWithValue("$loc", entry.Location);
            cmd.Parameters.AddWithValue("$name", entry.Name);
            cmd.Parameters.AddWithValue("$target", entry.Target);
            cmd.Parameters.AddWithValue("$bin", (object?)entry.TargetBinaryPath ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$first", entry.FirstSeenUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$last", entry.LastSeenUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$removed", (object?)entry.RemovedUtc?.ToUnixTimeMilliseconds() ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$installer", (object?)entry.InstallerExecutionId?.ToString("N") ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$author", (object?)entry.Author ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$trigger", (object?)entry.TriggerDescription ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sig", JsonSerializer.Serialize(entry.Signature, Json));
            cmd.ExecuteNonQuery();
        }
    }

    public void MarkPersistenceRemoved(string id, DateTimeOffset whenUtc)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE persistence_entries SET removed_utc=$when WHERE id=$id AND removed_utc IS NULL";
            cmd.Parameters.AddWithValue("$when", whenUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    public IReadOnlyList<PersistenceEntry> GetPersistenceEntries(bool includeRemoved = false)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, kind, location, name, target, target_binary, first_seen_utc, last_seen_utc, removed_utc, installer_execution_id, author, trigger_desc, sig_json FROM persistence_entries" +
                          (includeRemoved ? string.Empty : " WHERE removed_utc IS NULL") + " ORDER BY first_seen_utc DESC";
        return ReadPersistence(cmd);
    }

    public IReadOnlyList<PersistenceEntry> GetPersistenceForTarget(string binaryPathOrHash)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, kind, location, name, target, target_binary, first_seen_utc, last_seen_utc, removed_utc, installer_execution_id, author, trigger_desc, sig_json
            FROM persistence_entries
            WHERE target LIKE '%' || $q || '%' COLLATE NOCASE OR target_binary LIKE '%' || $q || '%' COLLATE NOCASE
            ORDER BY first_seen_utc DESC
            """;
        cmd.Parameters.AddWithValue("$q", binaryPathOrHash);
        return ReadPersistence(cmd);
    }

    private static List<PersistenceEntry> ReadPersistence(SqliteCommand cmd)
    {
        var result = new List<PersistenceEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            SignatureInfo sig;
            try
            {
                sig = reader.IsDBNull(12)
                    ? SignatureInfo.Unverified
                    : JsonSerializer.Deserialize<SignatureInfo>(reader.GetString(12), Json) ?? SignatureInfo.Unverified;
            }
            catch { sig = SignatureInfo.Unverified; }

            result.Add(new PersistenceEntry
            {
                Id = reader.GetString(0),
                Kind = (PersistenceKind)reader.GetInt32(1),
                Location = reader.GetString(2),
                Name = reader.GetString(3),
                Target = reader.GetString(4),
                TargetBinaryPath = reader.IsDBNull(5) ? null : reader.GetString(5),
                FirstSeenUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(6)),
                LastSeenUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(7)),
                RemovedUtc = reader.IsDBNull(8) ? null : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(8)),
                InstallerExecutionId = reader.IsDBNull(9) ? null : Guid.ParseExact(reader.GetString(9), "N"),
                Author = reader.IsDBNull(10) ? null : reader.GetString(10),
                TriggerDescription = reader.IsDBNull(11) ? null : reader.GetString(11),
                Signature = sig,
            });
        }
        return result;
    }

    public IReadOnlyList<TrustListEntry> GetTrustList()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256, path, signer, added_utc, note FROM trust_list";
        var result = new List<TrustListEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new TrustListEntry
            {
                Sha256 = reader.GetString(0),
                Path = reader.GetString(1),
                SignerSubject = reader.IsDBNull(2) ? null : reader.GetString(2),
                AddedUtc = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(3)),
                Note = reader.IsDBNull(4) ? null : reader.GetString(4),
            });
        }
        return result;
    }

    public void AddTrustListEntry(TrustListEntry entry)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO trust_list(sha256, path, signer, added_utc, note) VALUES ($sha, $path, $signer, $added, $note)
                ON CONFLICT(sha256) DO UPDATE SET path=excluded.path, signer=excluded.signer, note=excluded.note;
                """;
            cmd.Parameters.AddWithValue("$sha", entry.Sha256);
            cmd.Parameters.AddWithValue("$path", entry.Path);
            cmd.Parameters.AddWithValue("$signer", (object?)entry.SignerSubject ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$added", entry.AddedUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$note", (object?)entry.Note ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
    }

    public void RemoveTrustListEntry(string sha256)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM trust_list WHERE sha256=$sha";
            cmd.Parameters.AddWithValue("$sha", sha256);
            cmd.ExecuteNonQuery();
        }
    }

    public void SetVerdict(Guid executionId, UserVerdict verdict, string? notes)
    {
        if (GetExecution(executionId) is not { } exec) return;
        UpsertExecution(exec with { Verdict = verdict, UserNotes = notes });
    }

    public BaselineState LoadBaseline()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM baseline WHERE id=1";
        if (cmd.ExecuteScalar() is string json)
        {
            try
            {
                if (JsonSerializer.Deserialize<BaselineState>(json, Json) is { } state) return state;
            }
            catch { /* baseline corrompido → recomeça */ }
        }
        return new BaselineState
        {
            LearningStartedUtc = DateTimeOffset.UtcNow,
            LearningPeriod = BaselineEngine.DefaultLearningPeriod,
        };
    }

    public void SaveBaseline(BaselineState state)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO baseline(id, json) VALUES (1, $json) ON CONFLICT(id) DO UPDATE SET json=excluded.json";
            cmd.Parameters.AddWithValue("$json", JsonSerializer.Serialize(state, Json));
            cmd.ExecuteNonQuery();
        }
    }

    public void SaveSnapshot(MachineSnapshot snapshot)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO snapshots(taken_utc, label, json) VALUES ($taken, $label, $json)";
            cmd.Parameters.AddWithValue("$taken", snapshot.TakenUtc.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$label", (object?)snapshot.Label ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$json", JsonSerializer.Serialize(snapshot, Json));
            cmd.ExecuteNonQuery();
        }
    }

    public IReadOnlyList<MachineSnapshot> GetSnapshots()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM snapshots ORDER BY taken_utc DESC LIMIT 50";
        var result = new List<MachineSnapshot>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            try
            {
                if (JsonSerializer.Deserialize<MachineSnapshot>(reader.GetString(0), Json) is { } s) result.Add(s);
            }
            catch { /* ignora snapshot corrompido */ }
        }
        return result;
    }

    public RetentionResult PurgeAndSummarize(DateTimeOffset cutoffUtc, long maxDatabaseBytes)
    {
        lock (_writeLock)
        {
            using var conn = Open();
            int summarized;
            int purged;
            using (var tx = conn.BeginTransaction())
            {
                // 1. Sumariza execuções que vão expirar (eventos brutos → resumo estatístico)
                using (var sum = conn.CreateCommand())
                {
                    sum.Transaction = tx;
                    sum.CommandText = """
                        INSERT INTO execution_summaries(binary_key, file_name, image_path, run_count, first_utc, last_utc, max_score, total_upload_bytes)
                        SELECT COALESCE(e.sha256, lower(e.image_path)), e.file_name, e.image_path, COUNT(*),
                               MIN(e.created_utc), MAX(e.created_utc), MAX(e.score_total),
                               COALESCE((SELECT SUM(n.bytes_sent) FROM network_connections n
                                         WHERE n.execution_id IN (SELECT execution_id FROM executions e2
                                            WHERE COALESCE(e2.sha256, lower(e2.image_path)) = COALESCE(e.sha256, lower(e.image_path))
                                              AND e2.created_utc < $cutoff)), 0)
                        FROM executions e
                        WHERE e.created_utc < $cutoff
                        GROUP BY COALESCE(e.sha256, lower(e.image_path))
                        ON CONFLICT(binary_key) DO UPDATE SET
                            run_count = execution_summaries.run_count + excluded.run_count,
                            last_utc = MAX(execution_summaries.last_utc, excluded.last_utc),
                            max_score = MAX(execution_summaries.max_score, excluded.max_score),
                            total_upload_bytes = execution_summaries.total_upload_bytes + excluded.total_upload_bytes;
                        """;
                    sum.Parameters.AddWithValue("$cutoff", cutoffUtc.ToUnixTimeMilliseconds());
                    summarized = sum.ExecuteNonQuery();
                }

                // 2. Expurga eventos brutos antigos
                using (var purge = conn.CreateCommand())
                {
                    purge.Transaction = tx;
                    purge.CommandText = """
                        DELETE FROM network_connections WHERE execution_id IN (SELECT execution_id FROM executions WHERE created_utc < $cutoff);
                        DELETE FROM dns_queries WHERE execution_id IN (SELECT execution_id FROM executions WHERE created_utc < $cutoff);
                        DELETE FROM file_activities WHERE execution_id IN (SELECT execution_id FROM executions WHERE created_utc < $cutoff);
                        DELETE FROM module_loads WHERE execution_id IN (SELECT execution_id FROM executions WHERE created_utc < $cutoff);
                        DELETE FROM resource_samples WHERE execution_id IN (SELECT execution_id FROM executions WHERE created_utc < $cutoff);
                        DELETE FROM timeline_events WHERE ts_utc < $cutoff;
                        DELETE FROM executions WHERE created_utc < $cutoff;
                        """;
                    purge.Parameters.AddWithValue("$cutoff", cutoffUtc.ToUnixTimeMilliseconds());
                    purged = purge.ExecuteNonQuery();
                }
                tx.Commit();
            }

            // 3. Teto de disco: se ainda exceder, expurga os mais antigos restantes em blocos
            var dbBytes = DatabaseBytes();
            while (dbBytes > maxDatabaseBytes)
            {
                using var trim = conn.CreateCommand();
                trim.CommandText = """
                    DELETE FROM executions WHERE execution_id IN
                        (SELECT execution_id FROM executions ORDER BY created_utc LIMIT 500);
                    DELETE FROM timeline_events WHERE id IN
                        (SELECT id FROM timeline_events ORDER BY ts_utc LIMIT 2000);
                    """;
                if (trim.ExecuteNonQuery() == 0) break;
                Checkpoint(conn);
                var newSize = DatabaseBytes();
                if (newSize >= dbBytes) break; // não está encolhendo; evita loop infinito
                dbBytes = newSize;
            }

            Checkpoint(conn);
            return new RetentionResult(summarized, purged, DatabaseBytes());
        }
    }

    /// <summary>Checkpoint/compactação; intervalo configurável pelo coletor.</summary>
    public void Checkpoint()
    {
        if (_readOnly) return;
        lock (_writeLock)
        {
            using var conn = Open();
            Checkpoint(conn);
        }
    }

    private static void Checkpoint(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA incremental_vacuum;";
        cmd.ExecuteNonQuery();
    }

    private long DatabaseBytes()
    {
        long total = 0;
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            var f = new FileInfo(_dbPath + suffix);
            if (f.Exists) total += f.Length;
        }
        return total;
    }

    public StoreStats GetStats()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT (SELECT COUNT(*) FROM executions),
                   (SELECT COUNT(*) FROM timeline_events),
                   (SELECT MIN(created_utc) FROM executions),
                   (SELECT MAX(created_utc) FROM executions)
            """;
        using var reader = cmd.ExecuteReader();
        reader.Read();
        return new StoreStats(
            DatabaseBytes(),
            reader.GetInt32(0),
            reader.GetInt32(1),
            reader.IsDBNull(2) ? null : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2)),
            reader.IsDBNull(3) ? null : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(3)));
    }

    public void Dispose() => SqliteConnection.ClearAllPools();
}
