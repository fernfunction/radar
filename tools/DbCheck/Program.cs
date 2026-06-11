using Radar.Core.Abstractions;
using Radar.Core.Model;
using Radar.Data;

// Inspeção rápida do banco para validação fim-a-fim
var dbPath = args.Length > 0
    ? args[0]
    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "fradar", "radar.db");

using var store = new SqliteEventStore(dbPath, readOnly: true);
var stats = store.GetStats();
Console.WriteLine($"banco: {dbPath} ({stats.DatabaseBytes / 1024} KB, {stats.ExecutionCount} execuções)");

var executions = store.QueryExecutions(new ExecutionQuery { Limit = 500 });

// Distribuição de estados de assinatura
Console.WriteLine("\nEstados de assinatura:");
foreach (var g in executions.GroupBy(e => e.Binary.Signature.Status).OrderByDescending(g => g.Count()))
    Console.WriteLine($"  {g.Key}: {g.Count()}");

Console.WriteLine("\nExecuções com assinatura resolvida (amostra):");
foreach (var e in executions.Where(e => e.Binary.Signature.Status != SignatureStatus.Unknown).Take(8))
    Console.WriteLine($"  {e.Binary.FileName,-28} {e.Binary.Signature.Status,-18} {e.Binary.Signature.Subject ?? "-"}");

Console.WriteLine("\nDistribuição de score por faixa:");
foreach (var g in executions.GroupBy(e => Radar.Core.Analysis.SuspicionScore.BandFor(e.Score?.Muted == true ? 0 : e.Score?.Total ?? 0))
             .OrderBy(g => g.Key))
    Console.WriteLine($"  {g.Key}: {g.Count()}");
