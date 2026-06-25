using System.Drawing;
using System.Drawing.Imaging;

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: GenerateIcon <input.png> <output.ico>");
    return 1;
}

var pngPath = Path.GetFullPath(args[0]);
var icoPath = Path.GetFullPath(args[1]);

if (!File.Exists(pngPath))
{
    Console.Error.WriteLine($"PNG not found: {pngPath}");
    return 1;
}

Directory.CreateDirectory(Path.GetDirectoryName(icoPath)!);
WriteIconFromPng(pngPath, icoPath);
Console.WriteLine($"Icon created: {icoPath} ({new FileInfo(icoPath).Length:N0} bytes)");
return 0;

static void WriteIconFromPng(string pngPath, string icoPath)
{
    using var source = new Bitmap(pngPath);
    var sizes = new[] { 256, 128, 64, 48, 32, 16 };
    using var stream = new MemoryStream();
    using var writer = new BinaryWriter(stream);

    writer.Write((short)0);
    writer.Write((short)1);
    writer.Write((short)sizes.Length);

    var imageData = new List<byte[]>();
    var offset = 6 + 16 * sizes.Length;

    foreach (var size in sizes)
    {
        using var resized = new Bitmap(source, size, size);
        using var pngStream = new MemoryStream();
        resized.Save(pngStream, ImageFormat.Png);
        var data = pngStream.ToArray();
        imageData.Add(data);

        writer.Write((byte)(size >= 256 ? 0 : size));
        writer.Write((byte)(size >= 256 ? 0 : size));
        writer.Write((byte)0);
        writer.Write((byte)0);
        writer.Write((short)1);
        writer.Write((short)32);
        writer.Write(data.Length);
        writer.Write(offset);
        offset += data.Length;
    }

    foreach (var data in imageData)
    {
        writer.Write(data);
    }

    File.WriteAllBytes(icoPath, stream.ToArray());
}
