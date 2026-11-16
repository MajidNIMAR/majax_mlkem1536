"""Seal/replay the full local M09 check separately from its engine capsule."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

from archive_m09 import ROOT, members
from run_m07 import read, save, sha, require
from verify_m04_distribution import compiled_input_names


def log_result(raw):
    log = raw.decode('utf-8-sig')
    counts = list(re.finditer(r'(?m)^Ran (\d+) tests in [^\r\n]+\r?$',log))
    require(len(counts) == 1,'one complete Python suite required')
    require(log[counts[0].end():].lstrip().splitlines()[0].strip() == 'OK','Python suite failed')
    require(int(counts[0].group(1)) >= 352,'historical Python tests missing')
    require('Research arithmetic verification failed.' not in log and 'error: could not compile' not in log,
            'failed check log')
    return {'python_tests':int(counts[0].group(1))}


def analyze(folder):
    receipt = read(folder/'receipt.json')
    before = read(folder/'inputs-before.json')
    require(receipt['exit_code'] == 0 and receipt['compiled_sources_and_check_scripts_unchanged'] is True
            and before == receipt['inputs_after_sha256'] and sha(folder/'full-check.log') == receipt['log_sha256'],
            'full project check failed or controls/source changed')
    require(receipt['command'] == ['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/dev.ps1','check'],
            'full check command differs')
    for name in ('scripts/dev.ps1','scripts/dev.sh','.github/workflows/ci.yml','research/run_m09_check.py'):
        require(sha(folder/'controls'/name) == before[name],'executed check control differs')
    engine = read(folder/'engine-provenance.json')
    source_raw = (folder/'qualified-source.json').read_bytes()
    require(hashlib.sha256(source_raw).hexdigest() == engine['groups']['qualification']['files']['source.json']['sha256'],
            'checked source is not in qualified engine capsule')
    source = json.loads(source_raw)['source_sha256']
    compiled = {name:source[name] for name in compiled_input_names(source)}
    require(all(before.get(name) == checksum for name,checksum in compiled.items()),
            'full check did not cover the qualified compilation inputs')
    return {'schema':'m09-local-full-check-v1','exit_code':0,'qualified_compilation_inputs':len(compiled),
        'source_and_control_input_count':len(before),'source_and_controls_unchanged':True,
        **log_result((folder/'full-check.log').read_bytes()), 'fresh_long_fuzz_credit':0,'external_audit':False}


def freeze(source,output):
    require(source.parent == ROOT/'artifacts/generated' and source.is_dir()
            and output.parent == ROOT/'results/engine' and not output.exists(),'new check evidence capsule required')
    capsule = ROOT/'results/engine/m09-001'
    engine = read(capsule/'provenance.json')
    group = engine['groups']['qualification']
    require(sha(capsule/group['archive']) == group['archive_sha256'],'qualified engine archive differs')
    raw = members(capsule/group['archive'])['source.json']
    # Validate all data before creating a permanent result folder.
    receipt = read(source/'receipt.json')
    require(receipt['exit_code'] == 0,'cannot seal failed full check')
    log_result((source/'full-check.log').read_bytes())
    output.mkdir()
    shutil.copytree(source,output,dirs_exist_ok=True)
    shutil.copyfile(capsule/'provenance.json',output/'engine-provenance.json')
    (output/'qualified-source.json').write_bytes(raw)
    report = analyze(output)
    save(output/'verification.json',report)
    (output/'README.md').write_text('# M09 local full check\n\nFresh Windows fmt, strict Clippy, Rust tests, Python suite and required historical data replays. The receipt records original exit, unchanged source/control inputs and the qualified source map. Historical replay is not new acquisition credit.\n',encoding='utf-8')
    save(output/'provenance.json',{'schema':'m09-local-check-receipt-v1',
        'engine_provenance_sha256':sha(capsule/'provenance.json'),
        'output_sha256':{p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file()}})
    return verify(output)


def verify(output):
    provenance = read(output/'provenance.json')
    actual = {p.relative_to(output).as_posix():sha(p) for p in output.rglob('*')
              if p.is_file() and p != output/'provenance.json'}
    require(provenance['schema'] == 'm09-local-check-receipt-v1' and actual == provenance['output_sha256'],
            'full check capsule inventory differs')
    require(sha(output/'engine-provenance.json') == provenance['engine_provenance_sha256']
            == sha(ROOT/'results/engine/m09-001/provenance.json'),'engine/check capsule link differs')
    result = analyze(output)
    require(result == read(output/'verification.json'),'saved check conclusion differs')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('freeze','verify'))
    parser.add_argument('--source',type=Path,default=ROOT/'artifacts/generated/m09-check-002')
    parser.add_argument('--output',type=Path,default=ROOT/'results/engine/m09-verification-001')
    args = parser.parse_args()
    print(json.dumps(freeze(args.source.resolve(),args.output.resolve()) if args.action=='freeze' else verify(args.output.resolve()),indent=2))


if __name__ == '__main__':
    main()
