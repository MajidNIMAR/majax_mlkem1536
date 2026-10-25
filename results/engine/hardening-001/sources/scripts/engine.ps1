[CmdletBinding()]
param(
    [ValidateSet('build','check','self-test','vectors','stress','asm')]
    [string]$Task='self-test',
    [int]$Count=1000
)
$ErrorActionPreference='Stop'
$taskEngineRoot=Split-Path -Parent $PSScriptRoot
$env:CARGO_HOME=Join-Path $taskEngineRoot '.tools/cargo'
$env:RUSTUP_HOME=Join-Path $taskEngineRoot '.tools/rustup'
$env:CARGO_TARGET_DIR=Join-Path $taskEngineRoot 'target'
$taskEngineCargo=Join-Path $env:CARGO_HOME 'bin/cargo.exe'
$taskEngineSysroot=& (Join-Path $env:CARGO_HOME 'bin/rustc.exe') --print sysroot
if ($LASTEXITCODE -ne 0) { throw 'Local Rust sysroot unavailable.' }
foreach ($taskEngineToolDir in @(
    (Join-Path $taskEngineSysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained'),
    (Join-Path $taskEngineSysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin'),
    (Join-Path $taskEngineRoot '.tools/native-tools')
)) {
    if (Test-Path -LiteralPath $taskEngineToolDir -PathType Container) {
        $env:PATH=$taskEngineToolDir+[IO.Path]::PathSeparator+$env:PATH
    }
}
Push-Location -LiteralPath $taskEngineRoot
try {
    if ($Task -eq 'build') {
        & $taskEngineCargo build --locked --release -p kem1536-cli
    } elseif ($Task -eq 'asm') {
        & $taskEngineCargo rustc --locked --release -p kem1536 --features research-vectors --lib -- --emit=asm
    } elseif ($Task -eq 'vectors') {
        & $taskEngineCargo run --locked --release -p kem1536-cli --features research-vectors -- dev-vectors $Count
    } elseif ($Task -eq 'check') {
        & $taskEngineCargo clippy --locked --workspace --all-targets --all-features -- -D warnings
        if ($LASTEXITCODE -ne 0) { throw 'Engine Clippy failed.' }
        & $taskEngineCargo test --locked --workspace --all-features
    } elseif ($Task -eq 'stress') {
        & $taskEngineCargo run --locked --release -p kem1536-cli -- dev-stress $Count
    } else {
        & $taskEngineCargo run --locked --release -p kem1536-cli -- dev-self-test
    }
    if ($LASTEXITCODE -ne 0) { throw 'Engine task failed.' }
} finally { Pop-Location }
