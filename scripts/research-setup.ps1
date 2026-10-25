[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$taskResearchRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $taskResearchRoot
try {
    python -m venv .tools/research-venv
    if ($LASTEXITCODE -ne 0) { throw 'Research environment creation failed.' }
    & .tools/research-venv/Scripts/python.exe -m pip install -r research/requirements-research.txt
    if ($LASTEXITCODE -ne 0) { throw 'Research dependency installation failed.' }
    & .tools/research-venv/Scripts/python.exe research/upstream_tools.py --fetch
    if ($LASTEXITCODE -ne 0) { throw 'Pinned upstream research tools unavailable.' }
    & .tools/research-venv/Scripts/python.exe research/fetch_reference_copies.py --fetch
    if ($LASTEXITCODE -ne 0) { throw 'Pinned external reference copies unavailable.' }
}
finally { Pop-Location }
