$ErrorActionPreference = 'Stop'

Write-Host "AKE v1.0.0 Windows Release Build"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo was not found. Install the Rust toolchain first."
}

if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    throw "rustc was not found. Install the Rust toolchain first."
}

$target = $env:AKE_TARGET
if ([string]::IsNullOrWhiteSpace($target)) {
    $target = "x86_64-pc-windows-msvc"
}

Write-Host "Target: $target"
cargo build --release --target $target

$bin = Join-Path $PSScriptRoot "target\$target\release\ake.exe"
if (-not (Test-Path $bin)) {
    throw "Build completed without producing $bin"
}

& $bin --version
Write-Host "Release binary: $bin"
