using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Пакет доказательств: включённые файлы попадают в архив, манифест содержит
/// верные SHA-256 и метаданные дела, отсутствующие файлы отмечаются, а не рушат сборку.
/// </summary>
public sealed class EvidencePackageBuilderTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ufa-pkg-" + Guid.NewGuid().ToString("N"));

    public EvidencePackageBuilderTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
            {
                Directory.Delete(_dir, true);
            }
        }
        catch (IOException)
        {
        }
    }

    private string WriteFile(string name, string content)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    [Fact]
    public void Package_includes_files_and_manifest_with_correct_hashes()
    {
        var report = WriteFile("report.html", "<html>отчёт</html>");
        var journal = WriteFile("evidence.jsonl", "{\"a\":1}");
        var archivePath = Path.Combine(_dir, "package.zip");

        var result = EvidencePackageBuilder.Build(
            archivePath, [report, journal], examiner: "Орлов Д.В.", caseNumber: "ДЕЛО-42");

        Assert.Equal(2, result.IncludedFiles.Count);
        Assert.Empty(result.MissingFiles);
        Assert.True(File.Exists(archivePath));

        using var archive = ZipFile.OpenRead(archivePath);
        Assert.NotNull(archive.GetEntry("report.html"));
        Assert.NotNull(archive.GetEntry("evidence.jsonl"));

        var manifestEntry = archive.GetEntry("manifest.json");
        Assert.NotNull(manifestEntry);
        using var reader = new StreamReader(manifestEntry!.Open());
        using var doc = JsonDocument.Parse(reader.ReadToEnd());
        var root = doc.RootElement;

        Assert.Equal("UsbForensicAudit", root.GetProperty("Tool").GetString());
        Assert.Equal("Орлов Д.В.", root.GetProperty("Examiner").GetString());
        Assert.Equal("ДЕЛО-42", root.GetProperty("CaseNumber").GetString());

        var reportHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(report)));
        var manifestReport = root.GetProperty("Files").EnumerateArray()
            .First(x => x.GetProperty("File").GetString() == "report.html");
        Assert.Equal(reportHash, manifestReport.GetProperty("Sha256").GetString());
    }

    [Fact]
    public void Missing_file_is_reported_not_thrown()
    {
        var present = WriteFile("present.txt", "тут");
        var archivePath = Path.Combine(_dir, "pkg2.zip");

        var result = EvidencePackageBuilder.Build(
            archivePath, [present, Path.Combine(_dir, "нет-такого.txt")]);

        Assert.Single(result.IncludedFiles);
        Assert.Single(result.MissingFiles);
        Assert.True(File.Exists(archivePath));
    }
}
