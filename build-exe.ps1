param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$Version = "",
    [switch]$SkipEngineeringGuide
)

if ($Version -and $Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must match the X.Y.Z format, got: $Version"
}

$ErrorActionPreference = "Stop"
$publishScript = Join-Path $PSScriptRoot "scripts\publish-app.ps1"
$params = @{
    Configuration = $Configuration
    Runtime = $Runtime
    PublishDir = Join-Path $PSScriptRoot "bin\publish"
    GenerateEngineeringGuideIfMissing = -not $SkipEngineeringGuide
}

if ($Version) {
    $params["Version"] = $Version
}

if ($SkipEngineeringGuide) {
    $params["IncludeEngineeringGuide"] = $false
}

& $publishScript @params
