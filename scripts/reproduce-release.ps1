[CmdletBinding()]
param(
    [ValidateSet('prepare', 'windows', 'linux', 'all', 'verify', 'repackage')]
    [string]$Task = 'prepare',
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')]
    [string]$RunId = 'r1-001',
    [string]$Distribution = 'Ubuntu-22.04',
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')]
    [string]$ReferenceRunId = 'release-003'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskOutput = Join-Path $taskRoot "artifacts/generated/m04-distribution/$RunId"
$taskPython = Join-Path $taskRoot '.tools/research-venv/Scripts/python.exe'
$taskHelper = Join-Path $taskRoot 'research/verify_m04_distribution.py'
if (-not (Test-Path -LiteralPath $taskPython -PathType Leaf)) {
    throw 'Run scripts/research-setup.ps1 to install the local Python runtime first.'
}
function Invoke-DistributionPython {
    param([string[]]$Arguments)
    & $taskPython $taskHelper @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'M04 distribution verification failed.' }
}
if ($Task -eq 'prepare' -or ($Task -in @('all', 'repackage') -and -not (Test-Path -LiteralPath $taskOutput))) {
    Invoke-DistributionPython -Arguments @('snapshot', '--root', $taskRoot, '--output', $taskOutput)
}
if ($Task -eq 'prepare') { return }
if (-not (Test-Path -LiteralPath (Join-Path $taskOutput 'source-manifest.json'))) {
    throw 'Prepare a new source snapshot before compiling.'
}
if ($Task -eq 'repackage') {
    $taskReference = Join-Path $taskRoot "artifacts/generated/m04-distribution/$ReferenceRunId"
    $taskReuseArguments = @('repackage', '--snapshot', $taskOutput, '--reference', $taskReference)
    foreach ($taskValidation in Get-ChildItem -LiteralPath (Join-Path $taskRoot 'artifacts/generated') -Filter 'm04-delivery-contract-corrected-*.log' -File) {
        $taskReuseArguments += @('--validation-file', $taskValidation.FullName)
    }
    Invoke-DistributionPython -Arguments $taskReuseArguments
}
if ($Task -eq 'windows' -or $Task -eq 'all') {
    $taskNames = @('CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'RUSTUP_AUTO_INSTALL',
        'CARGO_TARGET_DIR', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTFLAGS', 'SOURCE_DATE_EPOCH',
        'CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS', 'CARGO_PROFILE_RELEASE_STRIP', 'PATH')
    $taskSaved = @{}
    foreach ($taskName in $taskNames) { $taskSaved[$taskName] = [Environment]::GetEnvironmentVariable($taskName, 'Process') }
    try {
        $env:CARGO_HOME = Join-Path $taskRoot '.tools/cargo'
        $env:RUSTUP_HOME = Join-Path $taskRoot '.tools/rustup'
        $env:RUSTUP_TOOLCHAIN = '1.91.1-x86_64-pc-windows-gnu'
        $env:RUSTUP_AUTO_INSTALL = '0'
        $env:CARGO_INCREMENTAL = '0'
        $env:CARGO_BUILD_JOBS = '2'
        $env:CARGO_PROFILE_RELEASE_STRIP = 'debuginfo'
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
        $taskCargo = Join-Path $env:CARGO_HOME 'bin/cargo.exe'
        $taskRustc = Join-Path $env:CARGO_HOME 'bin/rustc.exe'
        $taskSysroot = (& $taskRustc --print sysroot | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Pinned local GNU Rust toolchain unavailable.' }
        $taskRustVersion = (& $taskRustc -Vv | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $taskRustVersion -notmatch 'release: 1\.91\.1') {
            throw 'Rust 1.91.1 is required.'
        }
        foreach ($taskDir in @(
            (Join-Path $taskSysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained'),
            (Join-Path $taskSysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin'),
            (Join-Path $taskRoot '.tools/native-tools')
        )) { $env:PATH = $taskDir + [IO.Path]::PathSeparator + $env:PATH }
        $taskBuild = Join-Path $taskOutput 'windows'
        if (Test-Path -LiteralPath $taskBuild) { throw 'Windows build output already exists; use a new run ID.' }
        New-Item -ItemType Directory -Path $taskBuild | Out-Null
        $taskManifest = Get-Content -LiteralPath (Join-Path $taskOutput 'source-manifest.json') -Raw | ConvertFrom-Json
        $env:SOURCE_DATE_EPOCH = [string]$taskManifest.source_date_epoch
        $taskEnvironment = [ordered]@{
            target = 'x86_64-pc-windows-gnu'
            rustc = $taskRustVersion
            cargo = (& $taskCargo -V | Out-String).Trim()
            host = [Environment]::OSVersion.VersionString
            source_date_epoch = $env:SOURCE_DATE_EPOCH
            jobs = 2
            strip = 'debuginfo; symbol names retained for binary review'
            features = 'default CLI; research-vectors disabled'
            link_timestamp = 'disabled with --no-insert-timestamp'
            path_remaps = @('source=/source', 'target=/target', 'cargo=/cargo', 'rustup=/rustup')
            dependency_cache = 'shared preexisting local Cargo cache; --frozen --offline'
        }
        $taskEnvironment | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $taskBuild 'environment.json') -Encoding utf8
        foreach ($taskLetter in @('a', 'b')) {
            $taskOne = Join-Path $taskBuild "build-$taskLetter"
            $taskSource = Join-Path $taskOne 'source'
            $env:CARGO_TARGET_DIR = Join-Path $taskOne 'target'
            Invoke-DistributionPython -Arguments @('copy-source', '--snapshot', $taskOutput, '--destination', $taskSource)
            $taskFlags = @('-C', 'link-self-contained=yes', '-C', 'link-arg=-Wl,--no-insert-timestamp',
                "--remap-path-prefix=$taskSource=/source", "--remap-path-prefix=$env:CARGO_TARGET_DIR=/target",
                "--remap-path-prefix=$env:CARGO_HOME=/cargo", "--remap-path-prefix=$env:RUSTUP_HOME=/rustup")
            $env:CARGO_ENCODED_RUSTFLAGS = $taskFlags -join [char]31
            Push-Location -LiteralPath $taskSource
            try {
                & $taskCargo build --frozen --offline --release --target x86_64-pc-windows-gnu -p kem1536-cli --bin kem1536 --no-default-features --message-format=json-render-diagnostics 1> (Join-Path $taskOne 'cargo.jsonl') 2> (Join-Path $taskOne 'cargo.stderr.log')
                if ($LASTEXITCODE -ne 0) { throw "Windows isolated build $taskLetter failed; read cargo.stderr.log." }
                & $taskCargo metadata --frozen --offline --format-version 1 --filter-platform x86_64-pc-windows-gnu 1> (Join-Path $taskBuild "metadata-$taskLetter.json")
                if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
            } finally { Pop-Location }
            $taskBinary = Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-gnu/release/kem1536.exe'
            & $taskBinary dev-self-test 1> (Join-Path $taskOne 'self-test.json')
            if ($LASTEXITCODE -ne 0) { throw 'Shipped binary self-test failed.' }
            & $taskBinary dev-vectors 1> (Join-Path $taskOne 'research-disabled.stdout.log') 2> (Join-Path $taskOne 'research-disabled.stderr.log')
            if ($LASTEXITCODE -eq 0) { throw 'Research vectors are unexpectedly enabled.' }
        }
        $taskBinary = Join-Path $taskBuild 'build-a/target/x86_64-pc-windows-gnu/release/kem1536.exe'
        $taskWslBinary = (& wsl -d $Distribution -- wslpath -a ($taskBinary.Replace('\', '/')) | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'WSL path conversion for PE inspection failed.' }
        & wsl -d $Distribution -- objdump -p $taskWslBinary 1> (Join-Path $taskBuild 'native-dependencies.txt')
        if ($LASTEXITCODE -ne 0) { throw 'PE import inventory failed.' }
        Invoke-DistributionPython -Arguments @('seal', '--snapshot', $taskOutput, '--platform', 'windows', '--rust-root', $taskSysroot)
    } finally {
        foreach ($taskName in $taskNames) { [Environment]::SetEnvironmentVariable($taskName, $taskSaved[$taskName], 'Process') }
    }
}
if ($Task -eq 'linux' -or $Task -eq 'all') {
    $taskWslRoot = (& wsl -d $Distribution -- wslpath -a ($taskRoot.Replace('\', '/')) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'WSL project path conversion failed.' }
    $taskWslOutput = (& wsl -d $Distribution -- wslpath -a ($taskOutput.Replace('\', '/')) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'WSL snapshot path conversion failed.' }
    & wsl -d $Distribution -- bash "$taskWslRoot/scripts/reproduce-release-linux.sh" $taskWslOutput
    if ($LASTEXITCODE -ne 0) { throw 'Linux isolated distribution build failed.' }
}
Invoke-DistributionPython -Arguments @('verify', '--snapshot', $taskOutput)
