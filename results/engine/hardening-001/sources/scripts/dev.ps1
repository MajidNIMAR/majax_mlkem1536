[CmdletBinding()]
param(
    [ValidateSet('doctor', 'check', 'build', 'test', 'profile', 'status', 'fmt', 'clippy', 'reference', 'sources', 'analysis', 'modern')]
    [string]$Task = 'check'
)

$ErrorActionPreference = 'Stop'
$taskProjectRoot = Split-Path -Parent $PSScriptRoot
$env:CARGO_HOME = Join-Path $taskProjectRoot '.tools\cargo'
$env:RUSTUP_HOME = Join-Path $taskProjectRoot '.tools\rustup'
$env:CARGO_TARGET_DIR = Join-Path $taskProjectRoot 'target'
$env:PYTHONDONTWRITEBYTECODE = '1'
$taskRustBin = Join-Path $env:CARGO_HOME 'bin'
$taskCargo = Join-Path $taskRustBin 'cargo.exe'
$env:PATH = $taskRustBin + [IO.Path]::PathSeparator + $env:PATH

if (-not (Test-Path -LiteralPath $taskCargo -PathType Leaf)) {
    throw 'Local Rust tools missing. Run .\scripts\bootstrap.ps1 first.'
}

$taskSysroot = & (Join-Path $taskRustBin 'rustc.exe') --print sysroot
if ($LASTEXITCODE -ne 0) { throw 'Local Rust sysroot unavailable.' }
$taskNativeTools = Join-Path $taskSysroot 'lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained'
$taskHostTools = Join-Path $taskSysroot 'lib\rustlib\x86_64-pc-windows-gnu\bin'
$taskImportTools = Join-Path $taskProjectRoot '.tools\native-tools'
if (Test-Path -LiteralPath $taskNativeTools -PathType Container) {
    $env:PATH = $taskImportTools + [IO.Path]::PathSeparator + $taskHostTools + [IO.Path]::PathSeparator + $taskNativeTools + [IO.Path]::PathSeparator + $env:PATH
}

function Invoke-TaskCargo {
    param([string[]]$CargoArguments)
    & $taskCargo @CargoArguments
    if ($LASTEXITCODE -ne 0) { throw "Cargo failed: $($CargoArguments -join ' ')" }
}

Push-Location -LiteralPath $taskProjectRoot
try {
    switch ($Task) {
        'doctor' {
            Invoke-TaskCargo -CargoArguments @('--version')
            & (Join-Path $taskRustBin 'rustc.exe') --version --verbose
            if ($LASTEXITCODE -ne 0) { throw 'Rust compiler unavailable.' }
            python --version
            if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or newer is required for research scripts.' }
        }
        'check' {
            python research/verify_sources.py
            if ($LASTEXITCODE -ne 0) { throw 'Frozen source verification failed.' }
            Invoke-TaskCargo -CargoArguments @('fmt', '--all', '--', '--check')
            Invoke-TaskCargo -CargoArguments @('clippy', '--locked', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings')
            Invoke-TaskCargo -CargoArguments @('test', '--locked', '--workspace')
            Invoke-TaskCargo -CargoArguments @('test', '--locked', '--workspace', '--all-features')
            python research/check_profile.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent profile verification failed.' }
            $taskCheckResearchPython = Join-Path $taskProjectRoot '.tools/research-venv/Scripts/python.exe'
            if (-not (Test-Path -LiteralPath $taskCheckResearchPython -PathType Leaf)) {
                throw 'Pinned research runtime missing. Run scripts/research-setup.ps1 first.'
            }
            & $taskCheckResearchPython -m unittest discover -s research -p test_*.py
            if ($LASTEXITCODE -ne 0) { throw 'Research arithmetic verification failed.' }
            python research/verify_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Frozen research result verification failed.' }
            python research/verify_modern_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Modern research result verification failed.' }
            python research/verify_decapsulation_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Decapsulation diagnostic verification failed.' }
            python research/verify_u_dependency_results.py
            if ($LASTEXITCODE -ne 0) { throw 'U dependency study verification failed.' }
            python research/verify_witness_certificate.py
            if ($LASTEXITCODE -ne 0) { throw 'Rational correctness certificate verification failed.' }
            python research/verify_mixed_precision_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Mixed precision study verification failed.' }
            python research/verify_mixed_certificate_bits.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent bit-enumeration certificate replay failed.' }
            python research/verify_group_quantization_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Group quantization study verification failed.' }
            python research/verify_group_certificate_bits.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent group certificate verification failed.' }
            python research/compare_compression.py --verify
            if ($LASTEXITCODE -ne 0) { throw 'Matched-target compression comparison failed.' }
            python research/verify_coded_dual_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Coded dual result verification failed.' }
            python research/verify_coded_dual_refinement.py
            if ($LASTEXITCODE -ne 0) { throw 'Coded dual local stability verification failed.' }
            python research/verify_block_decoder_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Concrete block decoder result verification failed.' }
            python research/verify_block_decoder_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent concrete decoder verification failed.' }
            python research/verify_decoder_score_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Decoder score result verification failed.' }
            python research/verify_decoder_score_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent decoder score verification failed.' }
            python research/verify_cbd_decoder_results.py
            if ($LASTEXITCODE -ne 0) { throw 'CBD decoder comparison verification failed.' }
            python research/verify_cbd_decoder_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent CBD decoder verification failed.' }
            python research/verify_full_dual_toy_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Complete finite dual score verification failed.' }
            python research/verify_full_dual_toy_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent complete finite dual score verification failed.' }
            python research/verify_dual_expansion_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Expanded finite dual score verification failed.' }
            python research/verify_dual_expansion_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent expanded finite dual score verification failed.' }
            & $taskCheckResearchPython research/verify_higher_cbd_results.py
            if ($LASTEXITCODE -ne 0) { throw 'Higher-dimensional CBD score verification failed.' }
            & $taskCheckResearchPython research/verify_higher_cbd_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent higher-dimensional CBD score verification failed.' }
            python research/verify_score_transfer.py
            if ($LASTEXITCODE -ne 0) { throw 'Real-modulus score transfer audit failed.' }
            python research/verify_score_transfer_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent score transfer audit failed.' }
            & $taskCheckResearchPython research/verify_real_dual.py
            if ($LASTEXITCODE -ne 0) { throw 'Real-modulus dual list verification failed.' }
            & $taskCheckResearchPython research/verify_real_dual_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent real-modulus dual list verification failed.' }
            & $taskCheckResearchPython research/verify_additive_score.py
            if ($LASTEXITCODE -ne 0) { throw 'Additive score moment and selection verification failed.' }
            & $taskCheckResearchPython research/verify_additive_score_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent additive score verification failed.' }
            & $taskCheckResearchPython research/verify_cbd_fourth.py
            if ($LASTEXITCODE -ne 0) { throw 'Complete CBD fourth-moment verification failed.' }
            & $taskCheckResearchPython research/verify_cbd_fourth_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent complete CBD fourth-moment verification failed.' }
            & $taskCheckResearchPython research/verify_bounded_moments.py
            if ($LASTEXITCODE -ne 0) { throw 'Rational N32 moment verification failed.' }
            & $taskCheckResearchPython research/verify_bounded_moments_independent.py
            if ($LASTEXITCODE -ne 0) { throw 'Independent rational N32 moment verification failed.' }
            & $taskCheckResearchPython research/validate_engine_r1.py --limit 16
            if ($LASTEXITCODE -ne 0) { throw 'Frozen R1 engine vector replay failed.' }
            & $taskCheckResearchPython research/validate_rejections_r1.py --limit 16
            if ($LASTEXITCODE -ne 0) { throw 'Frozen R1 rejection replay failed.' }
            & $taskCheckResearchPython research/validate_hardening_m02.py --limit 16
            if ($LASTEXITCODE -ne 0) { throw 'M02 hardening evidence verification failed.' }
            Invoke-TaskCargo -CargoArguments @('run', '--locked', '--quiet', '-p', 'kem1536-cli', '--', 'dev-self-test')
            Invoke-TaskCargo -CargoArguments @('run', '--locked', '--quiet', '-p', 'kem1536-cli', '--', 'self-check')
        }
        'build' { Invoke-TaskCargo -CargoArguments @('build', '--locked', '--workspace') }
        'test' { Invoke-TaskCargo -CargoArguments @('test', '--locked', '--workspace') }
        'profile' { Invoke-TaskCargo -CargoArguments @('run', '--locked', '--quiet', '-p', 'kem1536-cli', '--', 'profile') }
        'status' { Invoke-TaskCargo -CargoArguments @('run', '--locked', '--quiet', '-p', 'kem1536-cli', '--', 'status') }
        'fmt' { Invoke-TaskCargo -CargoArguments @('fmt', '--all') }
        'clippy' { Invoke-TaskCargo -CargoArguments @('clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings') }
        'sources' {
            python research/verify_sources.py
            if ($LASTEXITCODE -ne 0) { throw 'Frozen source verification failed.' }
        }
        'analysis' {
            $taskResearchPython = Join-Path $taskProjectRoot '.tools/research-venv/Scripts/python.exe'
            if (-not (Test-Path -LiteralPath $taskResearchPython)) {
                throw 'Run scripts/research-setup.ps1 first.'
            }
            & $taskResearchPython research/run_j2.py
            if ($LASTEXITCODE -ne 0) { throw 'J2 research calculation failed.' }
        }
        'modern' {
            wsl -d Ubuntu-22.04 -- test -x .tools/sage-ram/env/bin/python
            if ($LASTEXITCODE -ne 0) {
                & (Join-Path $PSScriptRoot 'bootstrap-modern.ps1')
            }
            wsl -d Ubuntu-22.04 -- bash scripts/modern.sh --repair-export
            if ($LASTEXITCODE -ne 0) { throw 'Modern attack comparison failed.' }
        }
        'reference' {
            python research/verify_sources.py
            if ($LASTEXITCODE -ne 0) { throw 'Frozen source verification failed.' }
            $taskReferenceOutput = Invoke-TaskCargo -CargoArguments @('run', '--locked', '--quiet', '-p', 'kem1536-cli', '--', 'reference-1024')
            $taskReferenceText = $taskReferenceOutput -join [Environment]::NewLine
            $taskReferenceText | ConvertFrom-Json | Out-Null
            $taskReportDirectory = Join-Path $taskProjectRoot 'artifacts\generated'
            New-Item -ItemType Directory -Path $taskReportDirectory -Force | Out-Null
            [IO.File]::WriteAllText((Join-Path $taskReportDirectory 'reference-1024.json'), $taskReferenceText + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
            Write-Output $taskReferenceText
        }
    }
}
finally {
    Pop-Location
}

