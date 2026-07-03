param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$solution = Join-Path $PSScriptRoot "UsbForensicAudit.sln"
$project = Join-Path $PSScriptRoot "UsbForensicAudit.csproj"
$publishDir = Join-Path $PSScriptRoot "bin\publish"
$procmonDir = Join-Path $PSScriptRoot "tools"
$procmonExe = Join-Path $procmonDir "Procmon64.exe"
$procmonZip = Join-Path $procmonDir "ProcessMonitor.zip"
$procmonExtract = Join-Path $procmonDir "pmextract"
$infrastructureDll = Join-Path $PSScriptRoot "src\UsbForensicAudit.Infrastructure\bin\$Configuration\net8.0-windows\UsbForensicAudit.Infrastructure.dll"

function Ensure-ProcmonForOfflineBuild {
    New-Item -ItemType Directory -Force -Path $procmonDir | Out-Null
    if (Test-Path $procmonExe) {
        Write-Host "Procmon64.exe already present for offline bundle."
        return
    }

    Write-Host "Downloading Process Monitor (Procmon64.exe) for offline portable build..."
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/ProcessMonitor.zip" -OutFile $procmonZip
    if (Test-Path $procmonExtract) {
        Remove-Item $procmonExtract -Recurse -Force
    }
    Expand-Archive -Path $procmonZip -DestinationPath $procmonExtract -Force
    $found = Get-ChildItem -Path $procmonExtract -Filter "Procmon64.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) {
        $found = Get-ChildItem -Path $procmonExtract -Filter "Procmon.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $found) {
        throw "ProcessMonitor.zip does not contain Procmon64.exe"
    }

    Copy-Item $found.FullName $procmonExe -Force
    Remove-Item $procmonZip -Force -ErrorAction SilentlyContinue
    Remove-Item $procmonExtract -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Procmon64.exe prepared: $procmonExe"
}

function Prepare-BuildEnvironment {
    Get-Process -Name UsbForensicAudit -ErrorAction SilentlyContinue | Stop-Process -Force
    dotnet build-server shutdown 2>$null | Out-Null
}

function Test-EmbeddedProcmon {
    param([string]$DllPath)

    if (-not (Test-Path $DllPath)) {
        return $false
    }

    $escaped = $DllPath.Replace("'", "''")
    $command = @"
`$bytes = [System.IO.File]::ReadAllBytes('$escaped')
`$asm = [System.Reflection.Assembly]::Load(`$bytes)
if (`$asm.GetManifestResourceNames() -notcontains 'UsbForensicAudit.Tools.Procmon64.exe') { exit 1 }
exit 0
"@

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $command
    return $LASTEXITCODE -eq 0
}

Ensure-ProcmonForOfflineBuild
Prepare-BuildEnvironment

dotnet clean $solution -c $Configuration --nologo -v q

dotnet restore $solution

$iconTool = Join-Path $PSScriptRoot "tools\GenerateIcon\GenerateIcon.csproj"
$iconPng = Join-Path $PSScriptRoot "Assets\app-icon.png"
$iconOut = Join-Path $PSScriptRoot "Assets\app.ico"
if (Test-Path $iconPng) {
    dotnet run --project $iconTool -c $Configuration -- $iconPng $iconOut
} else {
    Write-Warning "Icon PNG not found: $iconPng"
}

foreach ($pattern in @("*.dll", "*.pdb")) {
    Get-ChildItem -Path $publishDir -Filter $pattern -ErrorAction SilentlyContinue | Remove-Item -Force
}
Remove-Item (Join-Path $publishDir "LatoFont") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $publishDir "Assets") -Recurse -Force -ErrorAction SilentlyContinue

dotnet publish $project `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:IncludeAllContentForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none `
    -o $publishDir

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

Get-ChildItem -Path $publishDir -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Warning "Unexpected file after single-file publish: $($_.Name)"
    Remove-Item $_.FullName -Force
}
Remove-Item (Join-Path $publishDir "LatoFont") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $publishDir "Assets") -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $publishDir -Filter "UsbForensicAudit.pdb" -ErrorAction SilentlyContinue | Remove-Item -Force

$manualProject = Join-Path $PSScriptRoot "tools\GenerateManual\GenerateManual.csproj"
$manualPath = Join-Path $publishDir "UsbForensicAudit-Instrukciya.pdf"

Get-ChildItem -Path $publishDir -Filter "UsbForensicAudit*.pdf" -ErrorAction SilentlyContinue | Remove-Item -Force

dotnet run --project $manualProject -c $Configuration -- $manualPath

if ($LASTEXITCODE -ne 0) {
    throw "GenerateManual failed with exit code $LASTEXITCODE"
}

$portableReadme = Join-Path $publishDir "PORTABLE.txt"
$readmeLines = @(
    'UsbForensicAudit - portable offline build'
    ''
    'Copy to USB flash drive / another PC:'
    '  UsbForensicAudit.exe'
    'Optional:'
    '  UsbForensicAudit-Instrukciya.pdf'
    ''
    'All work data is stored NEXT TO the exe (no traces in LocalAppData when writable):'
    '  data\tools\Procmon64.exe'
    '  data\procmon\<session>\capture.csv'
    '  data\audit.sqlite, app.log, reports...'
    ''
    'To remove all traces from a PC: delete the whole folder with exe + data\'
    ''
    'Internet on target PC is NOT required.'
    'Procmon is embedded inside the exe (offline-ready).'
    ''
    'Requires Windows 10/11 x64. Run as Administrator for full USB/registry/Procmon access.'
    'Third-party tools USBDetector.exe / USBDeview.exe are not included.'
)
Set-Content -Path $portableReadme -Value $readmeLines -Encoding UTF8

$publishedExe = Join-Path $publishDir "UsbForensicAudit.exe"
if (-not (Test-Path $publishedExe)) {
    throw "Published exe not found: $publishedExe"
}

if (-not (Test-EmbeddedProcmon $infrastructureDll)) {
    throw "Portable build verification failed: Procmon64.exe is not embedded in UsbForensicAudit.Infrastructure.dll ($infrastructureDll)"
}

Write-Host "Verified: Procmon64.exe is embedded (offline-ready)."

Write-Host "Published to: $publishDir"
Write-Host "Portable exe: $(Join-Path $publishDir 'UsbForensicAudit.exe')"
Write-Host "Manual PDF: $manualPath"
Write-Host "Note: copy UsbForensicAudit.exe to USB - all data goes to data\ folder next to exe."
