param(
    [string]$IdaRoot = "$env:PROGRAMFILES\IDA Professional 9.1",
    [string]$UserPluginRoot = "$env:APPDATA\Hex-Rays\IDA Pro\plugins",
    [switch]$InstallUserCopy
)

$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$targets = @((Join-Path $IdaRoot 'plugins'))
if ($InstallUserCopy) { $targets += $UserPluginRoot }
$required = @('Oo0l1IVvMm.py', 'seagull_core.py')

foreach ($target in $targets) {
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    foreach ($name in $required) {
        Copy-Item -LiteralPath (Join-Path $sourceRoot $name) -Destination (Join-Path $target $name) -Force
    }
    $vendor = Join-Path $target 'vendor'
    New-Item -ItemType Directory -Force -Path $vendor | Out-Null
    $capstoneSource = Join-Path $sourceRoot 'vendor\capstone'
    if (Test-Path (Join-Path $capstoneSource 'lib\capstone.dll')) {
        Copy-Item -LiteralPath $capstoneSource -Destination $vendor -Recurse -Force
    } elseif (-not (Get-Command python -ErrorAction SilentlyContinue) -or -not (python -c "import capstone" 2>$null)) {
        Write-Host 'NOTE: capstone not bundled and not importable. Set SEAGULL_CAPSTONE_PATH,
        or place a capstone package under plugins\vendor\capstone, or pip-install capstone
        into the Python that IDA uses.'
    }
    Write-Host "Installed Oo0l1IVvMm -> $target"
}

Write-Host 'Done. Restart IDA before testing.'
