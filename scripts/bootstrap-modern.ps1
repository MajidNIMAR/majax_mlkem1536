[CmdletBinding()]
param([string]$Distribution = 'Ubuntu-22.04')
$ErrorActionPreference = 'Stop'
$taskSageProject = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $taskSageProject
try {
    New-Item -ItemType Directory -Path .tools -Force | Out-Null
    $taskKeeperFile = Join-Path $taskSageProject '.tools/sage-keeper.pid'
    $taskKeeperRunning = $false
    if (Test-Path -LiteralPath $taskKeeperFile) {
        $taskKeeperId = [int](Get-Content -LiteralPath $taskKeeperFile)
        $taskKeeperProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$taskKeeperId"
        $taskKeeperRunning = $taskKeeperProcess -and $taskKeeperProcess.Name -eq 'wsl.exe' -and $taskKeeperProcess.CommandLine -like '*sleep 7200*'
    }
    if (-not $taskKeeperRunning) {
        # Keep the temporary runtime alive between commands in this work session.
        $taskKeeperProcess = Start-Process -FilePath 'wsl.exe' -ArgumentList @('-d', $Distribution, '--', 'sleep', '7200') -WindowStyle Hidden -PassThru
        [IO.File]::WriteAllText($taskKeeperFile, [string]$taskKeeperProcess.Id)
    }
    New-Item -ItemType Directory -Path .tools/sage-ram -Force | Out-Null
    wsl -d $Distribution -- mountpoint -q .tools/sage-ram
    if ($LASTEXITCODE -ne 0) {
        $taskSageUid = wsl -d $Distribution -- id -u
        $taskSageGid = wsl -d $Distribution -- id -g
        wsl -d $Distribution -u root -- mount -t tmpfs -o "size=6G,uid=${taskSageUid},gid=${taskSageGid}" tmpfs .tools/sage-ram
        if ($LASTEXITCODE -ne 0) { throw 'Unable to mount the project-local temporary Sage runtime.' }
    }
    wsl -d $Distribution -- bash scripts/bootstrap-modern.sh
    if ($LASTEXITCODE -ne 0) { throw 'Pinned local Sage setup failed.' }
}
finally { Pop-Location }
