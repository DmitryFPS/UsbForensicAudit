using UsbForensicAudit;

var outputPath = args.Length > 0
    ? args[0]
    : Path.Combine(AppContext.BaseDirectory, "UsbForensicAudit-Instrukciya.pdf");

try
{
    ManualPdfGenerator.Generate(outputPath);
    Console.WriteLine($"Manual PDF created: {outputPath}");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to create manual PDF: {ex.Message}");
    return 1;
}

return 0;
