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
$engineeringGuideDirectory = Join-Path $PSScriptRoot "docs"

function Assert-TrustedProcmon {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Procmon executable not found: $Path"
    }

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid `
        -or $signature.SignerCertificate.Subject -notmatch "(^|,\s*)O=Microsoft Corporation(,|$)") {
        throw "Procmon Authenticode signature is not trusted: $($signature.Status); $($signature.StatusMessage)"
    }
}

function Ensure-ProcmonForOfflineBuild {
    New-Item -ItemType Directory -Force -Path $procmonDir | Out-Null
    if (Test-Path $procmonExe) {
        Assert-TrustedProcmon $procmonExe
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
    Assert-TrustedProcmon $procmonExe
    Remove-Item $procmonZip -Force -ErrorAction SilentlyContinue
    Remove-Item $procmonExtract -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Procmon64.exe prepared: $procmonExe"
}

function Prepare-BuildEnvironment {
    if (Get-Process -Name UsbForensicAudit -ErrorAction SilentlyContinue) {
        throw "UsbForensicAudit is running. Close it before creating the portable build."
    }
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

dotnet restore $solution --locked-mode

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

Get-ChildItem -Path $publishDir -Filter "UsbForensicAudit*.pdf" -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item (Join-Path $publishDir "PORTABLE.txt") -Force -ErrorAction SilentlyContinue

$engineeringGuideSource = Get-ChildItem `
    -Path $engineeringGuideDirectory `
    -Filter "UsbForensicAudit_*.pdf" `
    -File `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $engineeringGuideSource) {
    throw "Engineering guide source not found in: $engineeringGuideDirectory"
}
$engineeringGuidePath = Join-Path $publishDir $engineeringGuideSource.Name
Copy-Item $engineeringGuideSource.FullName $engineeringGuidePath -Force

$publishedExe = Join-Path $publishDir "UsbForensicAudit.exe"
if (-not (Test-Path $publishedExe)) {
    throw "Published exe not found: $publishedExe"
}
foreach ($pdfPath in @($engineeringGuidePath)) {
    if (-not (Test-Path $pdfPath) -or (Get-Item $pdfPath).Length -lt 1000) {
        throw "Generated PDF is missing or invalid: $pdfPath"
    }
    $pdfSignature = [System.Text.Encoding]::ASCII.GetString(
        [System.IO.File]::ReadAllBytes($pdfPath),
        0,
        4)
    if ($pdfSignature -ne "%PDF") {
        throw "Generated file does not have a PDF signature: $pdfPath"
    }
}

if (-not (Test-EmbeddedProcmon $infrastructureDll)) {
    throw "Portable build verification failed: Procmon64.exe is not embedded in UsbForensicAudit.Infrastructure.dll ($infrastructureDll)"
}

Write-Host "Verified: Procmon64.exe is embedded (offline-ready)."

Write-Host "Published to: $publishDir"
Write-Host "Portable exe: $(Join-Path $publishDir 'UsbForensicAudit.exe')"
Write-Host "Engineering guide PDF: $engineeringGuidePath"
Write-Host "Note: copy UsbForensicAudit.exe to USB - all data goes to data\ folder next to exe."
