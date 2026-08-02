param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$PublishDir = "",
    [string]$Version = "",
    [switch]$SkipClean,
    [switch]$SkipIconGeneration,
    [switch]$SkipProcmonDownload,
    [switch]$IncludeEngineeringGuide,
    [switch]$RequireEngineeringGuide,
    [switch]$GenerateEngineeringGuideIfMissing,
    [switch]$VerifyEmbeddedProcmon,
    [switch]$SkipRunningProcessCheck
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$solution = Join-Path $repoRoot "UsbForensicAudit.sln"
$project = Join-Path $repoRoot "src\UsbForensicAudit\UsbForensicAudit.csproj"
if (-not $PublishDir) {
    $PublishDir = Join-Path $repoRoot "bin\publish"
}

$procmonDir = Join-Path $repoRoot "tools"
$procmonExe = Join-Path $procmonDir "Procmon64.exe"
$procmonZip = Join-Path $procmonDir "ProcessMonitor.zip"
$procmonExtract = Join-Path $procmonDir "pmextract"
$infrastructureDll = Join-Path $repoRoot "src\UsbForensicAudit.Infrastructure\bin\$Configuration\net10.0-windows\$Runtime\UsbForensicAudit.Infrastructure.dll"
$engineeringGuideDirectory = Join-Path $repoRoot "docs"
$generateGuideScript = Join-Path $PSScriptRoot "generate-engineering-guide.ps1"

if (-not $PSBoundParameters.ContainsKey("IncludeEngineeringGuide")) {
    $IncludeEngineeringGuide = $true
}
if (-not $PSBoundParameters.ContainsKey("VerifyEmbeddedProcmon")) {
    $VerifyEmbeddedProcmon = $true
}
if (-not $PSBoundParameters.ContainsKey("GenerateEngineeringGuideIfMissing")) {
    $GenerateEngineeringGuideIfMissing = $IncludeEngineeringGuide
}

if ($Version -and $Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must match the X.Y.Z format, got: $Version"
}

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
    if (-not $SkipRunningProcessCheck -and (Get-Process -Name UsbForensicAudit -ErrorAction SilentlyContinue)) {
        throw "UsbForensicAudit is running. Close it before creating the portable build."
    }
    # Гасим фоновые сборочные серверы предыдущего SDK, чтобы они не держали
    # файлы. cmd /c с редиректом внутри cmd — потому что в Windows PowerShell 5.1
    # конструкция `2>$null` на нативной команде при $ErrorActionPreference=Stop
    # превращает любую строку stderr в терминирующую NativeCommandError.
    cmd /c "dotnet build-server shutdown >nul 2>&1"
    # Команда опциональна (её может не быть в старых SDK) — сбой не критичен.
    $global:LASTEXITCODE = 0
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

function Resolve-EngineeringGuideSource {
    $existing = Get-ChildItem `
        -Path $engineeringGuideDirectory `
        -Filter "UsbForensicAudit_*.pdf" `
        -File `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($existing) {
        return $existing
    }

    if (-not $GenerateEngineeringGuideIfMissing) {
        return $null
    }

    Write-Host "Engineering guide PDF not found; generating from HTML..."
    & $generateGuideScript | Out-Null
    return Get-ChildItem `
        -Path $engineeringGuideDirectory `
        -Filter "UsbForensicAudit_*.pdf" `
        -File `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

if (-not $SkipProcmonDownload) {
    Ensure-ProcmonForOfflineBuild
}
Prepare-BuildEnvironment

dotnet restore $solution --locked-mode -r $Runtime
if ($LASTEXITCODE -ne 0) {
    throw "dotnet restore --locked-mode failed with exit code $LASTEXITCODE"
}

if (-not $SkipClean) {
    dotnet clean $solution -c $Configuration --nologo -v q
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet clean failed with exit code $LASTEXITCODE"
    }
}

if (-not $SkipIconGeneration) {
    $iconTool = Join-Path $repoRoot "tools\GenerateIcon\GenerateIcon.csproj"
    $iconPng = Join-Path $repoRoot "Assets\app-icon.png"
    $iconOut = Join-Path $repoRoot "Assets\app.ico"
    if (Test-Path $iconPng) {
        dotnet run --project $iconTool -c $Configuration -- $iconPng $iconOut
    } else {
        Write-Warning "Icon PNG not found: $iconPng"
    }
}

New-Item -ItemType Directory -Force -Path $PublishDir | Out-Null
foreach ($pattern in @("*.dll", "*.pdb")) {
    Get-ChildItem -Path $PublishDir -Filter $pattern -ErrorAction SilentlyContinue | Remove-Item -Force
}
Remove-Item (Join-Path $PublishDir "LatoFont") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $PublishDir "Assets") -Recurse -Force -ErrorAction SilentlyContinue

$versionArgs = @()
if ($Version) {
    $versionArgs = @(
        "-p:Version=$Version",
        "-p:AssemblyVersion=$Version.0",
        "-p:FileVersion=$Version.0"
    )
    Write-Host "Publishing with version: $Version"
}

dotnet publish $project `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    --no-restore `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:IncludeAllContentForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none `
    @versionArgs `
    -o $PublishDir

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

Get-ChildItem -Path $PublishDir -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Warning "Unexpected file after single-file publish: $($_.Name)"
    Remove-Item $_.FullName -Force
}
Remove-Item (Join-Path $PublishDir "LatoFont") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $PublishDir "Assets") -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $PublishDir -Filter "UsbForensicAudit.pdb" -ErrorAction SilentlyContinue | Remove-Item -Force

Get-ChildItem -Path $PublishDir -Filter "UsbForensicAudit*.pdf" -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item (Join-Path $PublishDir "PORTABLE.txt") -Force -ErrorAction SilentlyContinue

$engineeringGuidePath = $null
if ($IncludeEngineeringGuide) {
    $engineeringGuideSource = Resolve-EngineeringGuideSource
    if ($engineeringGuideSource) {
        $engineeringGuidePath = Join-Path $PublishDir $engineeringGuideSource.Name
        Copy-Item $engineeringGuideSource.FullName $engineeringGuidePath -Force
    } elseif ($RequireEngineeringGuide) {
        throw "Engineering guide PDF not found in: $engineeringGuideDirectory"
    } else {
        Write-Warning "Engineering guide PDF skipped (not found and -RequireEngineeringGuide not set)."
    }
}

$publishedExe = Join-Path $PublishDir "UsbForensicAudit.exe"
if (-not (Test-Path $publishedExe)) {
    throw "Published exe not found: $publishedExe"
}

if ($engineeringGuidePath) {
    if (-not (Test-Path $engineeringGuidePath) -or (Get-Item $engineeringGuidePath).Length -lt 1000) {
        throw "Bundled PDF is missing or invalid: $engineeringGuidePath"
    }
    $pdfSignature = [System.Text.Encoding]::ASCII.GetString(
        [System.IO.File]::ReadAllBytes($engineeringGuidePath),
        0,
        4)
    if ($pdfSignature -ne "%PDF") {
        throw "Bundled file does not have a PDF signature: $engineeringGuidePath"
    }
}

if ($VerifyEmbeddedProcmon -and -not (Test-EmbeddedProcmon $infrastructureDll)) {
    throw "Portable build verification failed: Procmon64.exe is not embedded in UsbForensicAudit.Infrastructure.dll ($infrastructureDll)"
}

if ($VerifyEmbeddedProcmon) {
    Write-Host "Verified: Procmon64.exe is embedded (offline-ready)."
}

Write-Host "Published to: $PublishDir"
Write-Host "Portable exe: $publishedExe"
if ($engineeringGuidePath) {
    Write-Host "Engineering guide PDF: $engineeringGuidePath"
}
Write-Host "Note: copy UsbForensicAudit.exe to USB - all data goes to data\ folder next to exe."
