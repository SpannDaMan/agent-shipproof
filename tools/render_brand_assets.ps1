param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$QaOutputPath = '',
    [string]$MasterPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$pluginRoot = Join-Path $Root 'plugins'
$manifestFiles = @(Get-ChildItem -LiteralPath $pluginRoot -Recurse -File -Filter 'Logo Generation Manifest *.json')
if ($manifestFiles.Count -ne 1) {
    throw "Expected exactly one logo generation manifest below $pluginRoot; found $($manifestFiles.Count)."
}

$manifestPath = $manifestFiles[0].FullName
$assetDir = Split-Path -Parent $manifestPath
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($required in @('canonical_master', 'master_sha256', 'master_width', 'master_height', 'mark_source', 'mark_source_sha256', 'shared_background_master', 'shared_background_sha256', 'source_type', 'source_background_policy', 'assets')) {
    if (-not $manifest.PSObject.Properties.Name.Contains($required)) {
        throw "Logo generation manifest is missing '$required'."
    }
}
if ($manifest.source_type -ne 'deterministic_exact_mark_composite') {
    throw "Unsupported source type '$($manifest.source_type)'."
}
if ($manifest.source_background_policy -ne 'opaque full-bleed silver satin') {
    throw "Unsupported background policy '$($manifest.source_background_policy)'."
}

function Resolve-PublicAsset([string]$RelativePath) {
    $resolved = Join-Path $Root $RelativePath
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Missing locked logo source: $RelativePath"
    }
    return $resolved
}

function Require-Hash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for $Path. Expected $Expected; got $actual."
    }
    return $actual
}

$canonical = Resolve-PublicAsset ([string]$manifest.canonical_master)
$mark = Resolve-PublicAsset ([string]$manifest.mark_source)
$background = Resolve-PublicAsset ([string]$manifest.shared_background_master)
Require-Hash $canonical ([string]$manifest.master_sha256) | Out-Null
Require-Hash $mark ([string]$manifest.mark_source_sha256) | Out-Null
Require-Hash $background ([string]$manifest.shared_background_sha256) | Out-Null

$master = [System.Drawing.Bitmap]::FromFile((Resolve-Path -LiteralPath $canonical))
try {
    if ($master.Width -ne [int]$manifest.master_width -or $master.Height -ne [int]$manifest.master_height -or $master.Width -ne $master.Height) {
        throw 'Canonical Silver Satin master dimensions do not match the manifest.'
    }
    $cornerAlpha = @($master.GetPixel(0, 0).A, $master.GetPixel($master.Width - 1, 0).A, $master.GetPixel(0, $master.Height - 1).A, $master.GetPixel($master.Width - 1, $master.Height - 1).A)
    if (@($cornerAlpha | Where-Object { $_ -ne 255 }).Count -gt 0) {
        throw "Silver Satin master must be opaque and full-bleed; corner alpha is $($cornerAlpha -join ',')."
    }
}
finally {
    $master.Dispose()
}

$outputs = @()
foreach ($name in @('icon.png', 'logo.png', 'logo-dark.png')) {
    $record = $manifest.assets.PSObject.Properties[$name].Value
    $path = Join-Path $assetDir $name
    Require-Hash $path ([string]$record.sha256) | Out-Null
    $image = [System.Drawing.Bitmap]::FromFile((Resolve-Path -LiteralPath $path))
    try {
        if ($image.Width -ne [int]$record.dimensions[0] -or $image.Height -ne [int]$record.dimensions[1]) {
            throw "Dimension mismatch for $name."
        }
        $cornerAlpha = @($image.GetPixel(0, 0).A, $image.GetPixel($image.Width - 1, 0).A, $image.GetPixel(0, $image.Height - 1).A, $image.GetPixel($image.Width - 1, $image.Height - 1).A)
        if (@($cornerAlpha | Where-Object { $_ -ne 255 }).Count -gt 0) {
            throw "$name must retain opaque full-bleed corners."
        }
    }
    finally {
        $image.Dispose()
    }
    $outputs += [ordered]@{ path = $path; sha256 = ([string]$record.sha256).ToLowerInvariant() }
}

[ordered]@{
    status = 'pass'
    source_policy = 'operator_locked_silver_satin_full_bleed'
    mutation = 'none_verify_only'
    canonical_master = $canonical
    outputs = $outputs
} | ConvertTo-Json -Depth 5
