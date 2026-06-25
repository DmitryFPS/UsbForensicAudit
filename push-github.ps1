# One-time script: initialize git history and push to GitHub.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .git)) {
    git init
    git branch -M main
}

if (git remote | Select-String -Pattern '^origin$' -Quiet) {
    git remote remove origin
}
git remote add origin https://github.com/DmitryFPS/UsbForensicAudit.git

function Commit-Group {
    param(
        [string]$Message,
        [string[]]$Paths
    )

    foreach ($path in $Paths) {
        if (Test-Path $path) {
            git add -- $path
        }
    }

    if ((git diff --cached --name-only).Count -eq 0) {
        Write-Host "SKIP (empty): $Message"
        return
    }

    git commit -m $Message
    Write-Host "OK: $Message"
}

Commit-Group "chore: add gitignore, README, and solution scaffold" @(
    ".gitignore",
    "README.md",
    "UsbForensicAudit.sln",
    "UsbForensicAudit.csproj",
    "app.manifest",
    "build-exe.ps1",
    "push-github.ps1"
)

Commit-Group "feat: core WPF shell and USB forensic collectors" @(
    "App.xaml",
    "App.xaml.cs",
    "MainWindow.xaml",
    "MainWindow.xaml.cs",
    "Models.cs",
    "AuditOrchestrator.cs",
    "AuditStorage.cs",
    "UsbRegistryCollector.cs",
    "SetupApiLogCollector.cs",
    "EventLogCollector.cs",
    "UserArtifactCollector.cs",
    "OfflineHiveCollector.cs",
    "ExecutionArtifactCollector.cs",
    "ProcessAttributionCollector.cs",
    "ConnectedDeviceIndex.cs",
    "CorrelationService.cs",
    "TimelineEnricher.cs",
    "OsInstallInfo.cs",
    "RegistryKeyTimestamps.cs",
    "ShellLinkParser.cs",
    "ArtifactStringExtractor.cs",
    "CompactVidPidParser.cs",
    "ReportService.cs",
    "ReportText.cs",
    "ForensicReportBuilder.cs",
    "TextSanitizer.cs",
    "DateDisplay.cs",
    "UserDisplayText.cs",
    "AdminHelper.cs",
    "AppLog.cs",
    "DataGridAutoSize.cs"
)

Commit-Group "feat: PDF/HTML reports, branding, and executive brief" @(
    "ForensicPdfReport.cs",
    "ExecutiveBriefPdfReport.cs",
    "ManualPdfGenerator.cs",
    "PdfFontHelper.cs",
    "AppBranding.cs",
    "DarkWindowChrome.cs",
    "Assets/app.ico",
    "Assets/app-icon.png",
    "Assets/Logo2.jpg"
)

Commit-Group "feat: live USB monitoring and active devices window" @(
    "LiveUsbDevice.cs",
    "LiveUsbSnapshotService.cs",
    "LiveDeviceMerger.cs",
    "LiveDeviceIdentity.cs",
    "LiveDeviceMetadataReader.cs",
    "WmiUsbMonitor.cs",
    "DeviceChangeNotifier.cs",
    "ActiveDevicesWindow.xaml",
    "ActiveDevicesWindow.xaml.cs",
    "RunningExternalUtilityScanner.cs"
)

Commit-Group "feat: cleanup traces, endpoint protection, and USB Oblivion attribution" @(
    "CleanupDetector.cs",
    "CleanupAttribution.cs",
    "CleanerToolCatalog.cs",
    "EndpointProtectionEventLogCollector.cs",
    "EndpointProtectionEnvironment.cs",
    "UsbOblivionAttributionAnalyzer.cs"
)

Commit-Group "feat: external utilities capture from USBDeview and USBDetector" @(
    "ExternalUtilityCatalog.cs",
    "ExternalUtilityModels.cs",
    "ExternalUtilitySupportServices.cs",
    "ExternalUtilityWindowCaptureService.cs",
    "Win32ListViewReader.cs",
    "Win32ListViewUiAutomationReader.cs",
    "Win32ListViewClipboardReader.cs",
    "Win32ControlEnumerator.cs",
    "ProcessBitnessHelper.cs"
)

Commit-Group "feat: external utility analysis UI, verdicts, and column normalization" @(
    "ExternalUtilityRowExplainer.cs",
    "ExternalUtilityRowAssessment.cs",
    "ExternalUtilityRowFormatter.cs",
    "ExternalUtilitySectionCatalog.cs",
    "ExternalUtilityIdentifierParser.cs",
    "ExternalUtilityColumnNormalizer.cs"
)

Commit-Group "feat: embed merged USB VID/PID database (usb.ids format)" @(
    "UsbVendorDatabase.cs",
    "UsbVendorDatabaseParser.cs",
    "Assets/USBVendors.txt",
    "tools/MergeUsbVendorDatabase",
    "tools/GenerateIcon",
    "tools/GenerateManual"
)

Commit-Group "test: unit tests and external utility integration harness" @(
    "tests",
    "tools/ExternalUtilityHarness"
)

# Anything left (e.g. new files)
git add -A
if ((git diff --cached --name-only).Count -gt 0) {
    git commit -m "chore: include remaining project files"
}

Write-Host ""
Write-Host "Commit history:"
git log --oneline

Write-Host ""
Write-Host "Pushing to origin/main..."
git push -u origin main

Write-Host "Done: https://github.com/DmitryFPS/UsbForensicAudit"
