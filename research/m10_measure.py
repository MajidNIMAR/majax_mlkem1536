"""Preregistered M09-to-M10 latency/memory comparison and data-only replay."""
import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import shutil
import statistics
import subprocess
from run_m07 import ROOT, read, require, save, sha, utc, linux
from m10_capture import inventory
from run_m09_qualification import checked, image
from run_m08 import validate_memory, MEMORY_OPERATIONS
from capture_m07_timing import affinity
from validate_hardening_m02 import command

OPS = ('keygen','encaps','decaps_valid','decaps_rejected')
ALLOC = ('alloc_calls','alloc_zeroed_calls','realloc_calls','dealloc_calls',
    'total_requested_bytes','retained_requested_bytes_at_api_return','peak_live_requested_bytes')
M09_CORE = {'crates/kem1536/src/dev_kem.rs':'e38b1bbda18844fdf33860a9ce60682822c9cbd99eb1c9a12759ebc8df2f9e46',
    'crates/kem1536/src/engine_poly.rs':'3de875c98b9dfd2d511d3774d263da24fdcfe03e917a90bbb6bcadd540a175b0',
    'crates/kem1536/src/secret_box.rs':'1dd2a0a29a05bd9dc57f73b7ddb56cb4b7cd2afffa2364d0ab945ce3744256b1'}
CONTROLS = ('m10_measure.py','m10_capture.py','run_m09_qualification.py','run_m08.py',
    'run_m07.py','build_m06_validation.py','capture_m07_timing.py',
    'analyze_delivery_timing.py','validate_hardening_m02.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def summarize_latency(rows, series):
    require(len(rows)==2000,'exactly 2000 observations per latency execution required')
    seen,groups = set(),defaultdict(list)
    for row in rows:
        require(set(row)=={'operation','series','iteration','nanoseconds'}
            and all(type(row[k]) is int for k in ('series','iteration','nanoseconds'))
            and row['series']==series and row['nanoseconds']>0,'invalid latency observation')
        key = (row['operation'],row['iteration'])
        require(row['operation'] in OPS and 0<=row['iteration']<500 and key not in seen,
            'duplicate/unknown latency observation')
        seen.add(key)
        groups[row['operation']].append(row['nanoseconds'])
    require(seen=={(op,i) for op in OPS for i in range(500)},'missing latency grid entry')
    return groups


def memory_budgets(base,candidate):
    result = {}
    for op in MEMORY_OPERATIONS[4:]:
        b,c = base[op],candidate[op]
        bm,cm = b['touched_stack_bytes']['maximum'],c['touched_stack_bytes']['maximum']
        alloc = {k:c['requested_allocation_ranges'][k][1]<=b['requested_allocation_ranges'][k][1] for k in ALLOC}
        result[op] = {'baseline_stack_max':bm,'candidate_stack_max':cm,
            'stack_passed':cm<=bm+1024,'allocation_budgets':alloc,
            'passed':cm<=bm+1024 and all(alloc.values())}
    return result


def evaluate_raws(raws):
    def data(name):
        return json.loads(raws[name])
    plan = data('plan.json')
    require(plan['schema']=='m10-measurement-plan-v1' and plan['series']==5 and plan['samples']==500
        and plan['warmup']==100 and plan['CPU']==10 and plan['median_ratio_max']==1.05
        and plan['p95_ratio_max']==1.20 and plan['stack_max_additional_bytes']==1024
        and plan['historical_CPU_credited']==0,'predefined M10 measurement scope differs')
    require(plan['controls_sha256']=={n.removeprefix('controls/'):digest(raw) for n,raw in raws.items()
        if n.startswith('controls/')} and set(plan['controls_sha256'])==set(CONTROLS),
        'measurement controller inventory differs')
    for label in ('baseline','candidate'):
        source = data('context/'+label+'-source.json')
        require(digest(raws['context/'+label+'-source.json'])==plan[label+'_source_manifest_sha256'],
            'source manifest differs')
        if label=='baseline':
            require(all(source['source_sha256'][n]==h for n,h in M09_CORE.items()),'baseline is not M09')
        for host in ('windows','linux'):
            build = data('context/'+label+'-'+host+'-build.json')
            require(build['source_manifest_sha256']==plan[label+'_source_manifest_sha256']
                and build['host']==host and build['profile']==source['profile']=='KEM1536-DEV-Q7681-R1',
                'source/build identity differs')
            for section,kind in (('images','latency'),('probes','probe')):
                binding = plan[section][host][label]
                require(build['binaries'][kind]['sha256']==binding['sha256']==digest(raws[binding['member']])
                    and build['binaries'][kind]['exit_code']==0,'measured image is not the qualified build')
    order = [(host,s,label) for host in ('windows','linux') for s in range(5)
        for label in (('baseline','candidate') if s%2==0 else ('candidate','baseline'))]
    runs = data('runs.json')
    require(len(runs)==20,'complete predefined AB/BA run count required')
    groups,memory = defaultdict(list),{}
    last_finish = datetime.fromisoformat(plan['created_utc'])
    for record,expected in zip(runs,order,strict=True):
        host,series,label = expected
        stem = f'{host}-{series}-{label}'
        binding = plan['images'][host][label]
        require(record==data(stem+'.receipt.json') and (record['host'],record['series'],record['label'])==expected
            and type(record['series']) is int and record['exit_code']==0 and type(record['exit_code']) is int,
            'latency execution identity/exit differs')
        require(record['command']==binding['command_prefix']+[str(series),'500','100']
            and record['binary_sha256']==binding['sha256']==digest(raws[binding['member']])
            and record['raw_sha256']==digest(raws[stem+'.jsonl'])
            and record['stderr_sha256']==digest(raws[stem+'.stderr']),'latency data/image binding differs')
        start,finish = (datetime.fromisoformat(record[k]) for k in ('started_utc','finished_utc'))
        require(last_finish<=start<=finish,'latency order/timestamps differ')
        last_finish = finish
        for op,values in summarize_latency([json.loads(line) for line in raws[stem+'.jsonl'].splitlines()],series).items():
            groups[host,label,op].extend(values)
    results = {}
    for host in ('windows','linux'):
        memory[host] = {}
        for label in ('baseline','candidate'):
            stem = f'memory-{host}-{label}'
            receipt = data(stem+'.receipt.json')
            binding = plan['probes'][host][label]
            require(receipt['exit_code']==0 and receipt['binary_sha256']==binding['sha256']==digest(raws[binding['member']])
                and receipt['raw_sha256']==digest(raws[stem+'.jsonl'])
                and receipt['stderr_sha256']==digest(raws[stem+'.stderr'])
                and receipt['command']==binding['command_prefix']+['3'],'memory data/image binding differs')
            memory[host][label] = validate_memory([json.loads(line) for line in raws[stem+'.jsonl'].splitlines()],3)
        panels = {}
        for op in OPS:
            stats = {}
            for label in ('baseline','candidate'):
                values = sorted(groups[host,label,op])
                require(len(values)==2500,'exact pooled observation count required')
                stats[label] = {'count':len(values),'median_ns':statistics.median(values),
                    'p95_ns':values[math.ceil(.95*len(values))-1]}
            med,p95 = (stats['candidate'][k]/stats['baseline'][k] for k in ('median_ns','p95_ns'))
            panels[op] = {**stats,'median_ratio':med,'p95_ratio':p95,'passed':med<=1.05 and p95<=1.20}
        budgets = memory_budgets(memory[host]['baseline'],memory[host]['candidate'])
        results[host] = {'latency':panels,'memory':budgets,
            'all_budgets_passed':all(p['passed'] for p in panels.values()) and all(p['passed'] for p in budgets.values())}
    return {'schema':'m10-measurements-v1','latency_observations':40000,'new_memory_observations':432,
        'baseline_memory_reused_observations':0,'hosts':results,
        'all_budgets_passed':all(p['all_budgets_passed'] for p in results.values()),
        'minimum_speed_gain_required':False,'historical_CPU_credited':0,
        'frequency_fixed':False,'global_host_isolation_proved':False,'constant_time_proved':False}


def evaluate(folder):
    return evaluate_raws({p.relative_to(folder).as_posix():p.read_bytes() for p in folder.rglob('*') if p.is_file()})


def acquire(candidate,baseline):
    candidate,baseline = candidate.resolve(),baseline.resolve()
    checked(candidate); checked(baseline)
    require(read(candidate/'execution/validate/after.json')['status']=='PASS','validate candidate before measurements')
    folder = candidate/'measurements'
    require(not folder.exists(),'new measurement acquisition required')
    folder.mkdir()
    for name in CONTROLS:
        dest = folder/'controls'/name
        dest.parent.mkdir(exist_ok=True)
        shutil.copyfile(ROOT/'research'/name,dest)
    controls = inventory(folder/'controls')
    (folder/'context').mkdir()
    for label,source in (('baseline',baseline),('candidate',candidate)):
        shutil.copyfile(source/'source.json',folder/'context'/(label+'-source.json'))
        for host in ('windows','linux'):
            shutil.copyfile(source/host/'build.json',folder/'context'/(label+'-'+host+'-build.json'))
    plan = {'schema':'m10-measurement-plan-v1','created_utc':utc(),'series':5,'samples':500,'warmup':100,'CPU':10,
        'median_ratio_max':1.05,'p95_ratio_max':1.20,'stack_max_additional_bytes':1024,
        'historical_CPU_credited':0,'baseline_source_manifest_sha256':sha(baseline/'source.json'),
        'candidate_source_manifest_sha256':sha(candidate/'source.json'),'controls_sha256':controls,'images':{},'probes':{}}
    for host in ('windows','linux'):
        plan['images'][host],plan['probes'][host] = {},{}
        for label,source in (('baseline',baseline),('candidate',candidate)):
            for kind,section in (('latency','images'),('probe','probes')):
                binary = image(source,host,kind)
                member = 'images/'+host+'-'+label+'-'+binary.name
                (folder/'images').mkdir(exist_ok=True)
                shutil.copyfile(binary,folder/member)
                prefix = command(binary,[])
                if host=='linux':
                    prefix = ['wsl','-d','Ubuntu-22.04','--','taskset','-c','10',linux(binary)]
                plan[section][host][label] = {'sha256':sha(binary),'member':member,'command_prefix':prefix}
    save(folder/'plan.json',plan)
    for host in ('windows','linux'):
        for label in ('baseline','candidate'):
            stem = f'memory-{host}-{label}'
            binding = plan['probes'][host][label]
            cmd = binding['command_prefix']+['3']
            started = utc()
            with affinity(10),(folder/(stem+'.jsonl')).open('xb') as log,(folder/(stem+'.stderr')).open('xb') as err:
                code = subprocess.run(cmd,stdout=log,stderr=err).returncode
            save(folder/(stem+'.receipt.json'),{'command':cmd,'exit_code':code,'binary_sha256':binding['sha256'],
                'raw_sha256':sha(folder/(stem+'.jsonl')),'stderr_sha256':sha(folder/(stem+'.stderr')),
                'started_utc':started,'finished_utc':utc()})
            require(code==0,'memory acquisition failed')
    runs = []
    for host in ('windows','linux'):
        for series in range(5):
            for label in (('baseline','candidate') if series%2==0 else ('candidate','baseline')):
                stem = f'{host}-{series}-{label}'
                binding = plan['images'][host][label]
                cmd = binding['command_prefix']+[str(series),'500','100']
                started = utc()
                with affinity(10),(folder/(stem+'.jsonl')).open('xb') as log,(folder/(stem+'.stderr')).open('xb') as err:
                    code = subprocess.run(cmd,stdout=log,stderr=err).returncode
                record = {'host':host,'series':series,'label':label,'command':cmd,'exit_code':code,
                    'binary_sha256':binding['sha256'],'raw_sha256':sha(folder/(stem+'.jsonl')),
                    'stderr_sha256':sha(folder/(stem+'.stderr')),'started_utc':started,'finished_utc':utc()}
                save(folder/(stem+'.receipt.json'),record)
                require(code==0,'latency acquisition failed')
                runs.append(record)
        print('M10 latency '+host+' complete',flush=True)
    save(folder/'runs.json',runs)
    checked(candidate); checked(baseline)
    require(controls=={n:sha(ROOT/'research'/n) for n in CONTROLS},'measurement controller changed during acquisition')
    result = evaluate(folder)
    save(folder/'evaluation.json',result)
    return result


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('acquire','verify'))
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,default=ROOT/'artifacts/generated/m10-baseline-001')
    args = parser.parse_args()
    print(json.dumps(acquire(args.candidate,args.baseline) if args.action=='acquire'
        else evaluate(args.candidate/'measurements'),indent=2))
