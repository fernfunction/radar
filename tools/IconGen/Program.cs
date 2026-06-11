using Radar.Collector;

// dotnet run --project tools/IconGen [caminho-de-saída]
var target = args.Length > 0 ? args[0] : "assets/radar.ico";

RadarArt.WriteIco(target, RadarArt.Normal, 16, 24, 32, 48, 64, 128, 256);
Console.WriteLine($"Ícone gravado em {Path.GetFullPath(target)}");
