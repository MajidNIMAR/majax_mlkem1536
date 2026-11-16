"""Build/validate a captured M10 closure with unchanged M09 instruments.

Instrument naming is historical; every image and observation here is new
and is bound to the supplied source capture, not to any M09 CPU credit.
"""
import argparse
from pathlib import Path
import shutil
import sys
from run_m07 import ROOT, read, require, save, sha, utc
from m10_capture import inventory
import run_m09_qualification as instrument

CONTROLS = ('m10_build.py','m10_capture.py','run_m09_qualification.py','build_m06_validation.py',
    'run_m07.py','run_m08.py','capture_m07_timing.py','validate_hardening_m02.py',
    'analyze_delivery_timing.py')
INPUTS = ('results/engine/r1-001/sources/research/kem_r1_reference.py',
    'results/engine/r1-001/vectors.jsonl.gz','results/engine/r1-001/provenance.json',
    'results/engine/r1-rejections-001/rejections.jsonl.gz',
    'results/engine/r1-rejections-001/provenance.json')


def bind(output, action):
    instrument.checked(output)
    folder = output/'execution'/action
    require(not folder.exists(),'new execution receipt required')
    folder.mkdir(parents=True)
    for name in CONTROLS:
        dest = folder/'controls'/name
        dest.parent.mkdir(exist_ok=True)
        shutil.copyfile(ROOT/'research'/name,dest)
    inputs = {name:sha(ROOT/name) for name in INPUTS} if action == 'validate' else {}
    for name in inputs:
        dest = folder/'inputs'/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,dest)
    before = {'started_utc':utc(),'action':action,'python':sys.version,
        'source_manifest_sha256':sha(output/'source.json'),
        'controls_sha256':inventory(folder/'controls'),'inputs_sha256':inputs,
        'new_builds':12 if action == 'build' else 0,'historical_CPU_credited':0}
    save(folder/'before.json',before)
    return folder,before


def execute(output, action):
    output = output.resolve()
    require(output.parent == ROOT/'artifacts/generated' and output.name.startswith('m10-'),
        'direct M10 generated capture required')
    folder,before = bind(output,action)
    failure = None
    try:
        if action == 'build':
            for host in ('windows','linux'):
                instrument.build(output,host)
        elif action == 'validate':
            instrument.validate(output)
        else:
            instrument.timing(output,10)
    except BaseException as error:
        failure = {'type':type(error).__name__,'message':str(error)}
        raise
    finally:
        controls = {name:sha(ROOT/'research'/name) for name in CONTROLS}
        inputs = {name:sha(ROOT/name) for name in before['inputs_sha256']}
        sources_unchanged = inventory(output/'source') == read(output/'source.json')['source_sha256']
        stable = (controls == before['controls_sha256'] and inputs == before['inputs_sha256']
            and sources_unchanged and sha(output/'source.json') == before['source_manifest_sha256'])
        save(folder/'after.json',{'finished_utc':utc(),'status':'PASS' if failure is None and stable else 'FAIL',
            'failure':failure,'sources_and_controls_and_inputs_unchanged':stable,
            'controls_sha256':controls,'inputs_sha256':inputs,
            'source_manifest_sha256':sha(output/'source.json'),'historical_CPU_credited':0})
        require(stable,'capture or execution controls changed during execution')
    return {'action':action,'status':'PASS','output':str(output),'new_builds':before['new_builds']}


if __name__ == '__main__':
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('build','validate','timing'))
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(execute(args.output,args.action),indent=2))
