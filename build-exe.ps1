param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "UsbForensicAudit.csproj"
$publishDir = Join-Path $PSScriptRoot "bin\publish"

dotnet restore $project

$iconTool = Join-Path $PSScriptRoot "tools\GenerateIcon\GenerateIcon.csproj"
$iconPng = Join-Path $PSScriptRoot "Assets\app-icon.png"
$iconOut = Join-Path $PSScriptRoot "Assets\app.ico"
if (Test-Path $iconPng) {
    dotnet run --project $iconTool -c $Configuration -- $iconPng $iconOut
} else {
    Write-Warning "Icon PNG not found: $iconPng"
}

dotnet publish $project `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -o $publishDir

$assetsPublish = Join-Path $publishDir "Assets"
New-Item -ItemType Directory -Force -Path $assetsPublish | Out-Null
Copy-Item (Join-Path $PSScriptRoot "Assets\app.ico") $assetsPublish -Force
Copy-Item (Join-Path $PSScriptRoot "Assets\app-icon.png") $assetsPublish -Force
if (Test-Path (Join-Path $PSScriptRoot "Assets\Logo2.jpg")) {
    Copy-Item (Join-Path $PSScriptRoot "Assets\Logo2.jpg") $assetsPublish -Force
}

$manualProject = Join-Path $PSScriptRoot "tools\GenerateManual\GenerateManual.csproj"
$manualPath = Join-Path $publishDir "UsbForensicAudit-Instrukciya.pdf"

Get-ChildItem -Path $publishDir -Filter "UsbForensicAudit*.pdf" -ErrorAction SilentlyContinue | Remove-Item -Force

dotnet run --project $manualProject -c $Configuration -- $manualPath

Write-Host "Published to: $publishDir"
Write-Host "Executable: $(Join-Path $publishDir 'UsbForensicAudit.exe')"
Write-Host "Manual PDF: $manualPath"
