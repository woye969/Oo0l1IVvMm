param(
    [string]$IdaRoot = 'C:\Users\jianr\Desktop\reverse\IDA Professional 9.1',
    [string]$UserPluginRoot = "$env:APPDATA\Hex-Rays\IDA Pro\plugins",
    [string]$HermesSitePackages = "$env:LOCALAPPDATA\hermes\hermes-agent\venv\Lib\site-packages",
    [switch]$InstallUserCopy
)

$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$targets = @((Join-Path $IdaRoot 'plugins'))
if ($InstallUserCopy) { $targets += $UserPluginRoot }
$required = @('ida_seagull_deob.py', 'seagull_core.py', 'README_seagull_deob.md')

foreach ($target in $targets) {
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    foreach ($name in $required) {
        Copy-Item -LiteralPath (Join-Path $sourceRoot $name) -Destination (Join-Path $target $name) -Force
    }
    $vendor = Join-Path $target 'vendor'
    New-Item -ItemType Directory -Force -Path $vendor | Out-Null
    $capstoneSource = Join-Path $sourceRoot 'vendor\capstone'
    if (-not (Test-Path $capstoneSource)) {
        $capstoneSource = Join-Path $HermesSitePackages 'capstone'
    }
    if (-not (Test-Path (Join-Path $capstoneSource 'lib\capstone.dll'))) {
        throw "Capstone package not found: $capstoneSource"
    }
    Copy-Item -LiteralPath $capstoneSource -Destination $vendor -Recurse -Force
    Write-Host "Installed Seagull 0.9.0 -> $target"
}

Write-Host 'F5 hook files and bundled Capstone are installed. Restart IDA before testing.'
