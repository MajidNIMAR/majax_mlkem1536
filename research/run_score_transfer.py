"""Freeze H09 diagnostics in a new directory below NIST."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

from score_transfer import audit_point

ROOT=Path(__file__).resolve().parents[1]
INPUTS=['docs/PROTOCOLE_H09.md','research/score_transfer.py','research/run_score_transfer.py',
        'research/test_score_transfer.py','research/verify_score_transfer.py',
        'research/verify_score_transfer_independent.py','research/coded_dual_model.py',
        'results/j2/run-009/study.json','results/j2/run-009/provenance.json',
        'results/j2/run-011/study.json','results/j2/run-011/residuals.jsonl',
        'results/j2/run-011/provenance.json']


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path,value):
    with path.open('x',encoding='utf-8',newline='\n') as f:
        json.dump(value,f,indent=2,allow_nan=False)
        f.write('\n')


def calculate():
    points=read(ROOT/'results/j2/run-009/study.json')['minima']
    residuals=[json.loads(s) for s in (ROOT/'results/j2/run-011/residuals.jsonl').read_text().splitlines()]
    return dict(protocol_commit='a0b9fab',points=[audit_point(p,i,residuals) for i,p in enumerate(points)],
                attack_costs_updated=False,profile_selected=False,j2_closed=False,
                scope='fixed-point sensitivity, conditional moments, explicit storage representations',
                limits=['no actual full dual list at q=7681','no certified population bias of concrete codes',
                        'no proved normal tail or full wrong-candidate moments',
                        'Cantelli sufficiency is not a necessary list size or attack cost',
                        'dense storage estimates are not universal memory lower bounds',
                        'no reoptimization or transfer of finite-q tail ratios'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT or output.exists():
        raise ValueError('new output directory below NIST required')
    value=calculate()
    output.mkdir(parents=True)
    write(output/'study.json',value)
    write(output/'provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
        protocol_commit='a0b9fab',python=platform.python_version(),
        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in INPUTS},
        output_sha256={'study.json':hashlib.sha256((output/'study.json').read_bytes()).hexdigest()}))
    print(json.dumps(value,indent=2))


if __name__=='__main__':
    main()
