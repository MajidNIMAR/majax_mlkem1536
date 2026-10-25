"""H13 rational N32 certificates and calibrations against frozen H12."""

import argparse
from datetime import datetime,timezone
from decimal import Decimal as D,localcontext
import hashlib
import json
from pathlib import Path
import platform
import time

from bounded_moments import certify,constant_certificate,fraction,numpy

ROOT=Path(__file__).resolve().parents[1]
PROTOCOL='5fc45d1'
METHODS=('norm','hash','energy')
INPUTS=['docs/PROTOCOLE_H13.md','research/bounded_moments.py','research/run_bounded_moments.py',
        'research/test_bounded_moments.py','research/verify_bounded_moments.py',
        'research/verify_bounded_moments_independent.py',
        'research/requirements-cbd-dimensions.txt','results/j2/run-017/banks.json',
        'results/j2/run-018/orders.json','results/j2/run-019/banks.json']


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def write(p,v):
    with p.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(v,stream,indent=2,allow_nan=False)
        stream.write('\n')


def log2(value):
    with localcontext() as ctx:
        ctx.prec=50
        return None if not value else float((D(value.numerator)/D(value.denominator)).ln()/D(2).ln())


def selected(parents,identifier,family,indices):
    b=next(r['bank'] for r in parents if r['bank']['identifier']==identifier and r['bank']['code']['family']==family)
    return [b['vectors'][i]['y']+b['vectors'][i]['x']+b['vectors'][i]['r'] for i in indices]


def calculate():
    constant_certificate()
    parents=read(ROOT/'results/j2/run-017/banks.json')
    orders=read(ROOT/'results/j2/run-018/orders.json')
    banks=[]
    timings=[]
    for identifier in range(4):
        for method in METHODS:
            ix=sorted(orders[identifier]['orders'][method][:32])
            for family in ('repeated','radix'):
                start=time.perf_counter()
                result=certify(selected(parents,identifier,family,ix),7681)
                banks.append(dict(identifier=identifier,method=method,family=family,indices=ix,certificate=result))
                timings.append(dict(identifier=identifier,method=method,family=family,seconds=time.perf_counter()-start))
        print(f'matrix {identifier}: six N32 certificates',flush=True)
    calibrations=[]
    old_geometries=read(ROOT/'results/j2/run-019/geometries.json')
    for old in read(ROOT/'results/j2/run-019/banks.json'):
        ix=next(g['indices'] for g in old_geometries if g['geometry_id']==old['geometry_id'])
        result=certify(selected(parents,old['identifier'],old['family'],ix),7681)
        for offset in old['population']['offsets']:
            for computed,saved in zip(result['orders'],offset['orders']):
                bound=fraction(computed['raw_correction_absolute_bound'])
                corr=saved['correction']
                if corr['sign'] and corr['log2_abs']>log2(bound)+1e-8:
                    raise ArithmeticError('H12 numeric correction outside rational bound')
        calibrations.append(dict(geometry_id=old['geometry_id'],identifier=old['identifier'],family=old['family'],certificate=result))
    groups=[]
    for method in METHODS:
        for family in ('repeated','radix'):
            bs=[b['certificate'] for b in banks if b['method']==method and b['family']==family]
            informative=all(b['centered']['variance_positive_certified'] for b in bs)
            largest=max((fraction(b['centered']['kurtosis_absolute_error_bound']) for b in bs),default=0) if informative else None
            groups.append(dict(method=method,family=family,all_variances_positive=informative,
                maximum_kurtosis_absolute_error=None if largest is None else float(largest),
                maximum_kurtosis_error_log2=None if largest is None else log2(largest)))
    summary=dict(protocol_commit=PROTOCOL,N=32,CBD_banks=len(banks),H12_calibration_banks=len(calibrations),
        H12_numeric_raw_moments_enclosed=len(calibrations)*16,uniform_in_all_offsets=True,
        rational_moment_bounds=True,full_probability_law_enumerated=False,rare_tail_certified=False,
        attack_costs_updated=False,profile_selected=False,j2_closed=False,groups=groups)
    return dict(constants=constant_certificate(),banks=banks,calibrations=calibrations,timings=timings,summary=summary)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT or output.exists():
        raise ValueError('new output directory below NIST required')
    result=calculate()
    output.mkdir(parents=True)
    for name,value in result.items():
        write(output/f'{name}.json',value)
    write(output/'provenance.json',dict(protocol_commit=PROTOCOL,created_utc=datetime.now(timezone.utc).isoformat(),
        python=platform.python_version(),numpy=numpy().__version__,
        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in INPUTS+['results/j2/run-019/geometries.json']},
        output_sha256={f'{n}.json':hashlib.sha256((output/f'{n}.json').read_bytes()).hexdigest() for n in result}))
    print(json.dumps(result['summary'],indent=2))


if __name__=='__main__':
    main()
