param(
    [string]$OutputPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$docsDir = Join-Path $repoRoot "docs"
$htmlFile = Get-ChildItem -Path $docsDir -Filter "UsbForensicAudit_*.html" -File -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $htmlFile) {
    throw "Engineering guide HTML not found in: $docsDir (expected UsbForensicAudit_*.html)"
}
$htmlPath = $htmlFile.FullName

if (-not $OutputPath) {
    $pdfName = [System.IO.Path]::ChangeExtension($htmlFile.Name, ".pdf")
    $OutputPath = Join-Path $docsDir $pdfName
}

if ((Test-Path $OutputPath) -and -not $Force) {
    Write-Host "Engineering guide PDF already exists: $OutputPath"
    return $OutputPath
}

function Find-HeadlessBrowser {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    return $null
}

$browser = Find-HeadlessBrowser
if (-not $browser) {
    throw "No headless browser found (Edge or Chrome required to render HTML to PDF)."
}

$outDir = Split-Path $OutputPath -Parent
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
if (Test-Path $OutputPath) {
    Remove-Item $OutputPath -Force
}

$htmlUri = [Uri]::new((Resolve-Path -LiteralPath $htmlPath).ProviderPath).AbsoluteUri
Write-Host "Rendering engineering guide PDF via $browser"
& $browser `
    --headless `
    --disable-gpu `
    --no-pdf-header-footer `
    --run-all-compositor-stages-before-draw `
    --virtual-time-budget=10000 `
    "--print-to-pdf=$OutputPath" `
    $htmlUri | Out-Null

# Edge/Chrome headless may return a non-zero exit code even when the PDF is written.
if (-not (Test-Path $OutputPath) -or (Get-Item $OutputPath).Length -lt 1000) {
    throw "Headless browser did not produce a valid PDF (exit code $LASTEXITCODE)."
}

$signature = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($OutputPath), 0, 4)
if ($signature -ne "%PDF") {
    throw "Generated file does not have a PDF signature: $OutputPath"
}

Write-Host "Engineering guide PDF created: $OutputPath"
return $OutputPath
