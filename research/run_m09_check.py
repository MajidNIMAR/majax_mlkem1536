"""Record a new full project check with source/control hashes before and after."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from build_m06_validation import source_files
from run_m07 import save, require, sha

ROOT = Path(__file__).resolve().parents[1]


def run(output):
    require(output.parent == ROOT/'artifacts/generated' and not output.exists(), 'new local check directory required')
    output.mkdir()
    paths = sorted(set(source_files()+list((ROOT/'research').glob('*.py'))
        +[ROOT/'scripts/dev.ps1',ROOT/'scripts/dev.sh',ROOT/'.github/workflows/ci.yml']))
    inventory = lambda: {p.relative_to(ROOT).as_posix():sha(p) for p in paths}
    before = inventory()
    save(output/'inputs-before.json',before)
    for name in ('scripts/dev.ps1','scripts/dev.sh','.github/workflows/ci.yml','research/run_m09_check.py'):
        destination = output/'controls'/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,destination)
    command = ['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/dev.ps1','check']
    started = datetime.now(timezone.utc).isoformat()
    with (output/'full-check.log').open('xb') as log:
        result = subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
    after = inventory()
    receipt = {'command':command,'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),
        'exit_code':result.returncode,'compiled_sources_and_check_scripts_unchanged':before==after,
        'inputs_after_sha256':after,'log_sha256':sha(output/'full-check.log'),
        'source_and_control_input_count':len(before),'historical_CPU_credit':0}
    save(output/'receipt.json',receipt)
    print(json.dumps({key:value for key,value in receipt.items() if key!='inputs_after_sha256'}),flush=True)
    require(result.returncode == 0 and before==after,'full check failed or source/control changed; all traces retained')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/generated/m09-check-002')
    run(parser.parse_args().output.resolve())


if __name__ == '__main__':
    main()
