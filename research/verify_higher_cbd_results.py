"""Pinned-runtime replay of H08 integer laws, geometry links and all scores."""

import hashlib
import json
from pathlib import Path

from higher_cbd import array_hash,case_data,evaluate,fingerprint,law,make_bank,numpy,score_data
from run_higher_cbd import as_fraction,summarize
from verify_full_dual_toy_results import compare

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/j2/run-015'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def verify():
    np=numpy()
    for name in ('provenance.json','independent-provenance.json'):
        data=read(RUN/name)
        for group,base in (('input_sha256',ROOT),('output_sha256',RUN)):
            for name,expected in data[group].items():
                path=(base/name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                    raise ValueError(f'H08 checksum mismatch: {name}')
    provenance=read(RUN/'provenance.json')
    if provenance['protocol_commit']!='128c463' or provenance['numpy']!=np.__version__:
        raise ValueError('H08 protocol/runtime mismatch')
    cases=read(RUN/'cases.json')
    if len(cases)!=16 or {(c['m'],c['l'],c['identifier']) for c in cases}!={(m,l,i) for m,l in ((2,1),(3,2)) for i in range(8)}:
        raise ValueError('H08 architecture coverage failed')
    for c in cases:
        compare(c,case_data(c['m'],c['l'],c['identifier']))
    panels=read(RUN/'panels.json')
    banks=[json.loads(s) for s in (RUN/'banks.jsonl').read_text().splitlines()]
    table=next(t for t in read(ROOT/'results/j2/run-013/transcendental-tables.json') if t['q']==17)
    by_case={c['case']:c for c in cases}
    by_bank={b['bank_id']:b for b in banks}
    expected={(c['case'],source,N,family,metric,eta) for c in cases for source in ('reference','lll_box') for N in (4,8,12)
              for family in ('repeated','radix') for metric in ('euclidean','cbd') for eta in (1,2,3)}
    if len(panels)!=1152 or {(p['case'],p['source'],p['N'],p['family'],p['metric'],p['eta']) for p in panels}!=expected:
        raise ValueError('H08 panel coverage failed')
    links={}
    used=set()
    for p in panels:
        key=p['case'],p['source'],p['N'],p['family'],p['metric']
        if key not in links:
            links[key]=fingerprint(make_bank(by_case[p['case']],p['source'],p['N'],p['family'],p['metric'],table['cbd_weights']))
        if p['bank_id']!=links[key]:
            raise ValueError('H08 eta/geometry sharing failed')
        used.add(p['bank_id'])
    if used!=set(by_bank) or len(by_bank)!=len(banks):
        raise ValueError('H08 duplicate/missing bank')
    laws={}
    law_records=read(RUN/'laws.json')
    if len(law_records)!=96:
        raise ValueError('H08 96 laws required')
    for r in law_records:
        c=by_case[r['case']]
        a=law(c['A'],r['g'],r['eta'])
        if list(a.shape)!=r['shape'] or array_hash(a)!=r['sha256'] or int(a.sum())!=r['denominator']:
            raise ValueError('H08 integer law failed')
        laws[r['case'],tuple(r['g']),r['eta']]=a
    matrix_case={fingerprint(c['A']):c['case'] for c in cases}
    count=0
    for r in banks:
        bank=r['bank']
        if fingerprint(bank)!=r['bank_id'] or set(r['results'])!={'1','2','3'}:
            raise ValueError('H08 saved bank failed')
        data=score_data(bank,table['cosine_weights'])
        if data['hashes']!=r['score_hashes']:
            raise ValueError('H08 complete phase/score array failed')
        compare(data['DFT_delta'],r['maximum_DFT_delta'])
        c=matrix_case[fingerprint(bank['A'])]
        for eta in (1,2,3):
            compare(evaluate(bank,laws[c,tuple(bank['g']),eta],data,eta),r['results'][str(eta)])
        count+=data['integers'].size
    old_banks={r['bank_id']:r for r in (json.loads(s) for s in (ROOT/'results/j2/run-014/banks.jsonl').read_text().splitlines())}
    old_panels={(p['case'],p['source'],p['N'],p['family'],p['metric']):p for p in read(ROOT/'results/j2/run-014/panels.json')}
    calibrated=0
    for p in panels:
        c=by_case[p['case']]
        if c['dimension']!=3 or p['eta']!=1:
            continue
        prior=old_panels[f"q17-matrix{c['identifier']}",p['source'],p['N'],p['family'],p['metric']]
        old=old_banks[prior['bank_id']]['result']
        new=by_bank[p['bank_id']]['results']['1']
        for name in ('strict_success','true_in_argmax','uniform_tie_success'):
            if as_fraction(old[name])!=as_fraction(new[name]):
                raise ValueError('H08 exact H07 calibration failed')
        calibrated+=1
    summary=summarize(cases,panels,banks)
    summary['control_CBD1_calibrations']=calibrated
    compare(summary,read(RUN/'summary.json'))
    independent=read(RUN/'independent-verification.json')
    if calibrated!=192 or not independent['exact_hashes_and_events_matched'] or independent['exact_laws_verified']!=96 or independent['complete_guess_scores']!=count or independent['distinct_score_banks']!=len(banks):
        raise ValueError('H08 independent/calibration coverage failed')
    return dict(snapshot='run-015',matrices=16,LLL_certificates=16,panels=1152,exact_CBD_laws=96,
                distinct_score_banks=len(banks),complete_guess_scores=int(count),H07_exact_calibrations=192,
                maximum_bit_denominator=2**54,attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
