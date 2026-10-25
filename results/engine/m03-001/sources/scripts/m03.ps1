[CmdletBinding()]
param([ValidateSet('build','measure')][string]$Task='build')
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$env:CARGO_HOME=Join-Path $taskRoot '.tools/cargo'
$env:RUSTUP_HOME=Join-Path $taskRoot '.tools/rustup'
$env:CARGO_TARGET_DIR=Join-Path $taskRoot 'target/m03-windows'
$taskCargo=Join-Path $env:CARGO_HOME 'bin/cargo.exe'
$taskSysroot=& (Join-Path $env:CARGO_HOME 'bin/rustc.exe') --print sysroot
if ($LASTEXITCODE -ne 0) { throw 'Rust sysroot unavailable.' }
foreach ($taskDir in @(
    (Join-Path $taskSysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained'),
    (Join-Path $taskSysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin'),
    (Join-Path $taskRoot '.tools/native-tools')
)) { $env:PATH=$taskDir+[IO.Path]::PathSeparator+$env:PATH }
Push-Location -LiteralPath $taskRoot
try {
    if ($Task -eq 'build') {
        & $taskCargo build --locked --release -p kem1536-bench -p kem1536-cli
    } else {
        & (Join-Path $env:CARGO_TARGET_DIR 'release/kem1536-bench.exe') measure
    }
    if ($LASTEXITCODE -ne 0) { throw 'M03 task failed.' }
} finally { Pop-Location }
