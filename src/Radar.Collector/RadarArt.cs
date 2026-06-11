using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

namespace Radar.Collector;

/// <summary>
/// Fonte única da arte do "radar": o ícone da bandeja e o ícone do programa (.exe / janela)
/// são desenhados pela mesma geometria, garantindo que sejam idênticos. A geometria é autorada a
/// 32px e escala para qualquer tamanho.
/// </summary>
internal static class RadarArt
{
    public static readonly Color Normal = Color.FromArgb(0x10, 0x7C, 0x10);    // verde: coletando
    public static readonly Color Paused = Color.FromArgb(0x98, 0x6F, 0x0B);    // âmbar: pausado
    public static readonly Color Error = Color.FromArgb(0x75, 0x75, 0x75);     // cinza: degradado
    public static readonly Color Critical = Color.FromArgb(0xC5, 0x0F, 0x1F);  // vermelho: crítico
    public static readonly Color Background = Color.FromArgb(0x20, 0x20, 0x20);

    /// <summary>Desenha o radar (escala a partir do desenho-base de 32px) sobre fundo transparente.</summary>
    public static void Draw(Graphics g, float size, Color accent)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);
        var s = size / 32f;

        using var bg = new SolidBrush(Background);
        g.FillEllipse(bg, 1 * s, 1 * s, 30 * s, 30 * s);
        using var pen = new Pen(accent, 2.4f * s);
        g.DrawEllipse(pen, 4 * s, 4 * s, 24 * s, 24 * s);
        g.DrawEllipse(pen, 10 * s, 10 * s, 12 * s, 12 * s);
        g.DrawLine(pen, 16 * s, 16 * s, 27 * s, 7 * s);
        using var dot = new SolidBrush(accent);
        g.FillEllipse(dot, 13.5f * s, 13.5f * s, 5 * s, 5 * s);
    }

    /// <summary>Ícone em runtime para a bandeja (sem assets externos).</summary>
    public static Icon CreateIcon(int size, Color accent)
    {
        using var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp)) Draw(g, size, accent);
        return Icon.FromHandle(bmp.GetHicon());
    }

    /// <summary>
    /// Gera um arquivo .ico multi-resolução (entradas PNG, suportadas no Windows Vista+), usado
    /// pelo gerador para produzir o ícone do programa a partir da mesma arte da bandeja.
    /// </summary>
    public static void WriteIco(string path, Color accent, params int[] sizes)
    {
        var images = new List<byte[]>(sizes.Length);
        foreach (var size in sizes)
        {
            using var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp)) Draw(g, size, accent);
            using var ms = new MemoryStream();
            bmp.Save(ms, ImageFormat.Png);
            images.Add(ms.ToArray());
        }

        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        using var fs = new FileStream(path, FileMode.Create);
        using var w = new BinaryWriter(fs);
        w.Write((short)0);              // reservado
        w.Write((short)1);              // tipo = ícone
        w.Write((short)sizes.Length);   // número de imagens

        var offset = 6 + 16 * sizes.Length;
        for (var i = 0; i < sizes.Length; i++)
        {
            var size = sizes[i];
            w.Write((byte)(size >= 256 ? 0 : size)); // largura (0 = 256)
            w.Write((byte)(size >= 256 ? 0 : size)); // altura
            w.Write((byte)0);   // nº de cores na paleta (0 = sem paleta)
            w.Write((byte)0);   // reservado
            w.Write((short)1);  // planos de cor
            w.Write((short)32); // bits por pixel
            w.Write(images[i].Length);
            w.Write(offset);
            offset += images[i].Length;
        }
        foreach (var img in images) w.Write(img);
    }
}
