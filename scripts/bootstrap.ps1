[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$taskProjectRoot = Split-Path -Parent $PSScriptRoot
$env:CARGO_HOME = Join-Path $taskProjectRoot '.tools\cargo'
$env:RUSTUP_HOME = Join-Path $taskProjectRoot '.tools\rustup'
$env:RUSTUP_INIT_SKIP_PATH_CHECK = 'yes'
$taskInstaller = Join-Path $taskProjectRoot '.tools\downloads\rustup-init.exe'
$taskRustup = Join-Path $env:CARGO_HOME 'bin\rustup.exe'

if (-not (Test-Path -LiteralPath $taskRustup -PathType Leaf)) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $taskInstaller) -Force | Out-Null
    Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $taskInstaller
    & $taskInstaller -y --no-modify-path --profile minimal --default-host x86_64-pc-windows-gnu --default-toolchain none
    if ($LASTEXITCODE -ne 0) { throw 'Rustup installation failed.' }
}

& $taskRustup toolchain install 1.91.1-x86_64-pc-windows-gnu --profile minimal --component rustfmt --component clippy --component llvm-tools-preview
if ($LASTEXITCODE -ne 0) { throw 'Rust toolchain installation failed.' }
$taskSysroot = & $taskRustup run 1.91.1-x86_64-pc-windows-gnu rustc --print sysroot
if ($LASTEXITCODE -ne 0) { throw 'Rust sysroot lookup failed.' }
$taskLlvmAr = Join-Path $taskSysroot 'lib\rustlib\x86_64-pc-windows-gnu\bin\llvm-ar.exe'
$taskNativeDirectory = Join-Path $taskProjectRoot '.tools\native-tools'
New-Item -ItemType Directory -Path $taskNativeDirectory -Force | Out-Null
# LLVM's archiver also implements dlltool, selected by the executable name.
Copy-Item -LiteralPath $taskLlvmAr -Destination (Join-Path $taskNativeDirectory 'dlltool.exe') -Force
Write-Output 'Local toolchain ready. Run .\scripts\dev.ps1 check'

