"""Capture a new M10 source closure without building or modifying earlier evidence."""
import argparse
from pathlib import Path
import shutil
import subprocess
from build_m06_validation import source_files
from run_m07 import ROOT, require, save, sha, utc


def inventory(folder):
    return {p.relative_to(folder).as_posix():sha(p) for p in sorted(folder.rglob('*')) if p.is_file()}


def capture(output, label):
    output = output.resolve()
    require(output.parent == ROOT/'artifacts/generated' and output.name.startswith('m10-')
            and not output.exists(), 'new direct M10 generated child required')
    paths = set(source_files())
    for name in ('research/m08-memory-probe','research/m08-import-consumer','fuzz'):
        parent = ROOT/name
        paths.update(p for p in parent.rglob('*') if p.is_file()
            and not set(p.relative_to(parent).parts) & {'target','corpus','artifacts','coverage'})
    paths.update(ROOT/p for p in ('LICENSE','NOTICE','THIRD_PARTY_NOTICES.md',
        'docs/SPECIFICATION_DEV_Q7681_R1.md','docs/PROTOCOLE_M10.md','research/m10-campaign-plan.json',
        'research/m10_capture.py'))
    output.mkdir()
    for path in sorted(paths):
        require(path.resolve().is_relative_to(ROOT) and path.is_file() and not path.is_symlink(),
                'ordinary captured source required')
        dest = output/'source'/path.relative_to(ROOT)
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,dest)
    manifest = {'schema':'m10-source-capture-v1','profile':'KEM1536-DEV-Q7681-R1',
        'label':label,'captured_utc':utc(),'head_commit':subprocess.check_output(
            ['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'working_diff':subprocess.check_output(['git','diff','--','crates','fuzz'],cwd=ROOT,text=True),
        'source_sha256':inventory(output/'source'),'new_builds':0}
    save(output/'source.json',manifest)
    return {'output':str(output),'files':len(manifest['source_sha256']),
            'manifest_sha256':sha(output/'source.json'),'new_builds':0}


if __name__ == '__main__':
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--label',required=True)
    args = parser.parse_args()
    print(json.dumps(capture(args.output,args.label),indent=2))
