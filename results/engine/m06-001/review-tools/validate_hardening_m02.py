"""M02 cross-platform regression, independent mutations and timing diagnostics."""

import argparse
from datetime import datetime,timezone
import gzip
import hashlib
import importlib.util
import itertools
import json
import math
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/engine/hardening-001'
PARENT=ROOT/'results/engine/r1-001'
REJECT=ROOT/'results/engine/r1-rejections-001'
SOURCES=['Cargo.toml','Cargo.lock','rust-toolchain.toml','crates/kem1536/Cargo.toml',
    'crates/kem1536-cli/Cargo.toml','crates/kem1536/src/lib.rs','crates/kem1536/src/dev_kem.rs',
    'crates/kem1536/src/engine_poly.rs','crates/kem1536/src/secret_box.rs',
    'crates/kem1536/src/dev_hardening.rs','crates/kem1536-cli/src/main.rs',
    'research/validate_hardening_m02.py','docs/PROTOCOLE_DURCISSEMENT_M02.md']


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def write(p,v):
    with p.open('x',encoding='utf-8',newline='\n') as out:
        json.dump(v,out,indent=2,allow_nan=False);out.write('\n')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def command(binary,operation):
    if binary.suffix=='.exe':
        return [str(binary),*operation]
    posix='/mnt/'+binary.drive[0].lower()+str(binary)[2:].replace('\\','/')
    return ['wsl','-d','Ubuntu-22.04','--',posix,*operation]


def lines(binary,operation):
    with subprocess.Popen(command(binary,operation),stdout=subprocess.PIPE) as process:
        try:
            yield from process.stdout
        except BaseException:
            process.terminate();process.wait();raise
        if process.wait()!=0:
            raise ValueError(f'failed research operation: {operation}')


def regression(binary):
    counts={}
    for operation,source,expected in [('dev-vectors',PARENT/'vectors.jsonl.gz',1000),
            ('dev-rejection-vectors',REJECT/'rejections.jsonl.gz',10000)]:
        args=[operation,'1000'] if operation=='dev-vectors' else [operation]
        with gzip.open(source,'rb') as saved:
            count=0
            for a,b in itertools.zip_longest(lines(binary,args),saved):
                if a is None or b is None or json.loads(a)!=json.loads(b):
                    raise ValueError(f'R1 byte regression: {operation}/{count}')
                count+=1
        if count!=expected:
            raise ValueError('regression coverage missing')
        counts[operation]=count
    return dict(binary_sha256=sha(binary),compared_to_frozen_M01=counts,all_fields_equal=True)


def oracle():
    path=PARENT/'sources/research/kem_r1_reference.py'
    spec=importlib.util.spec_from_file_location('m02_frozen_oracle',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if module.np.__version__!='2.3.5':
        raise ValueError('pinned NumPy 2.3.5 required')
    return module


def mutations(stream,ref,limit=None):
    d,z,_=ref.synthetic_seeds(0);_,dk=ref.keygen(d,z)
    classes=[0]*5;accepted=[0]*5;unique=set();digest=hashlib.sha256()
    count=0
    for line in stream:
        if limit is not None and count>=limit:
            break
        row=json.loads(line)
        if row['case']!=count or row['class']!=count%5:
            raise ValueError('mutation order differs')
        c=bytes(row['ciphertext']);result,valid=ref.decapsulate(dk,c)
        if valid!=row['accepted'] or bytes(row['shared'])!=result:
            raise ValueError(f'independent mutation differs at {count}')
        classes[row['class']]+=1;accepted[row['class']]+=int(valid)
        unique.add(hashlib.sha256(c).digest());digest.update(c);digest.update(result)
        count+=1
    return dict(cases=count,class_counts=classes,accepted_counts=accepted,
        distinct_ciphertexts=len(unique),ciphertext_and_secret_sha256=digest.hexdigest(),
        independent_decrypt_and_reencrypt=True)


def timing_summary(rows):
    if len(rows)!=6000 or [r['sequence'] for r in rows]!=list(range(6000)):
        raise ValueError('timing sequence incomplete')
    groups=[]
    for label in range(3):
        samples=[r['nanoseconds'] for r in rows if r['class']==label]
        if len(samples)!=2000 or any(x<1 for x in samples):
            raise ValueError('timing classes missing')
        groups.append(dict(label=label,count=len(samples),mean_ns=statistics.mean(samples),
            variance_ns=statistics.variance(samples),median_ns=statistics.median(samples),
            minimum_ns=min(samples),maximum_ns=max(samples)))
    pairs=[]
    for i,j in itertools.combinations(range(3),2):
        a,b=groups[i],groups[j]
        denominator=math.sqrt(a['variance_ns']/a['count']+b['variance_ns']/b['count'])
        t=(a['mean_ns']-b['mean_ns'])/denominator if denominator else 0.
        pairs.append(dict(classes=[i,j],welch_t=t,threshold=4.5,signal=abs(t)>=4.5))
    return dict(warmup=100,observations_per_class=2000,groups=groups,pairs=pairs,
        signal_detected=any(p['signal'] for p in pairs),constant_time_proven=False)


def extract_probes(source):
    text=source.read_text(encoding='utf-8')
    output={}
    for name in ('reduce_probe','quotient_probe'):
        match=re.search(r'^(_ZN[^\n:]*'+name+r'[^\n:]*):\s*$',text,re.M)
        if match is None:
            raise ValueError('assembly probe missing')
        rest=text[match.start():]
        end=re.search(r'^\s*(?:\.seh_endproc|\.Lfunc_end\d+:)',rest,re.M)
        if end is None:
            raise ValueError('assembly function boundary missing')
        body=rest[:end.end()]
        instructions=re.findall(r'^\t([a-z][a-z0-9]*)\s',body,re.M)
        conditional=[x for x in instructions if x.startswith('j') and x not in ('jmp','jmpq')]
        divisions=[x for x in instructions if re.fullmatch(r'i?div[bwlq]?',x)]
        if conditional or divisions:
            raise ValueError('assembly probe has conditional branch or division')
        output[name]=dict(assembly=body,instructions=instructions,conditional_branches=conditional,
            divisions=divisions,scope='two scalar probes only')
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate',action='store_true')
    parser.add_argument('--windows-binary',type=Path)
    parser.add_argument('--linux-binary',type=Path)
    parser.add_argument('--output',type=Path,default=RUN)
    parser.add_argument('--limit',type=int)
    args=parser.parse_args();output=args.output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT:
        raise ValueError('new local output required')
    ref=oracle()
    if args.generate:
        if output.exists() or args.limit is not None or args.windows_binary is None or args.linux_binary is None:
            raise ValueError('new output and two research builds required')
        binaries={'windows':args.windows_binary.resolve(),'linux':args.linux_binary.resolve()}
        if any(not p.is_relative_to(ROOT) for p in binaries.values()):
            raise ValueError('local build paths required')
        output.mkdir(parents=True);start=time.perf_counter()
        hashes={k:sha(p) for k,p in binaries.items()}
        platforms={}
        for name,binary in binaries.items():
            print(f'{name}: full R1 regression',flush=True)
            platforms[name]=regression(binary)
            platforms[name]['formats']=json.loads(subprocess.check_output(command(binary,['dev-hardening'])))
            if platforms[name]['formats']['inputs']!=20000:
                raise ValueError('format campaign missing')
        if platforms['windows']['formats']!=platforms['linux']['formats']:
            raise ValueError('format counts differ across platforms')
        write(output/'platforms.json',platforms)
        with (output/'mutations.jsonl.gz').open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed:
            def stream():
                for line in lines(binaries['windows'],['dev-mutations']):
                    compressed.write(line);yield line
            mutation_result=mutations(stream(),ref)
        if mutation_result['cases']!=10000:
            raise ValueError('mutation coverage missing')
        write(output/'mutations.json',mutation_result)
        print('windows: 10000 mutations independently verified',flush=True)
        with gzip.open(output/'mutations.jsonl.gz','rb') as saved:
            count=0
            for a,b in itertools.zip_longest(lines(binaries['linux'],['dev-mutations']),saved):
                if a is None or b is None or json.loads(a)!=json.loads(b):
                    raise ValueError('Linux mutation output differs')
                count+=1
        if count!=10000:
            raise ValueError('Linux mutations incomplete')
        print('linux: 10000 identical mutation results',flush=True)
        # Expensive regression and mutation work is complete before this measurement.
        rows=[json.loads(line) for line in lines(binaries['windows'],['dev-timing'])]
        with gzip.open(output/'timing.jsonl.gz','wt',encoding='utf-8',newline='\n') as out:
            for row in rows:
                out.write(json.dumps(row,separators=(',',':'))+'\n')
        measured=timing_summary(rows);write(output/'timing.json',measured)
        assembly={}
        for name,folder in [('windows',ROOT/'target/release/deps'),('linux',ROOT/'target/linux/release/deps')]:
            candidates=[p for p in folder.glob('kem1536-*.s') if 'reduce_probe' in p.read_text(encoding='utf-8')]
            if not candidates:
                raise ValueError('assembly build required')
            source=max(candidates,key=lambda p:p.stat().st_mtime)
            assembly[name]=extract_probes(source)
        write(output/'assembly.json',assembly)
        environment=dict(platform=platform.platform(),python=platform.python_version(),
            numpy=ref.np.__version__,linux_runtime='Ubuntu-22.04 under WSL2',
            compiler_pin=(ROOT/'rust-toolchain.toml').read_text(),binary_sha256=hashes)
        write(output/'environment.json',environment)
        result=dict(protocol_commit='63fd895',engine_source_commit='6dae419',profile='KEM1536-DEV-Q7681-R1',
            windows_and_linux_regression_equal=True,vectors_per_platform=1000,rejections_per_platform=10000,
            format_inputs_per_platform=20000,mutations_per_platform=10000,
            independently_verified_mutations=10000,timing=measured,
            elapsed_seconds=time.perf_counter()-start,security_validation='pending',constant_time_proven=False)
        write(output/'summary.json',result)
        inputs={}
        for name in SOURCES:
            copy=output/'sources'/name;copy.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,copy)
            inputs[copy.relative_to(ROOT).as_posix()]=sha(copy)
        for run in (PARENT,REJECT):
            for name in ('provenance.json','validation.json'):
                p=run/name;inputs[p.relative_to(ROOT).as_posix()]=sha(p)
        p=PARENT/'sources/research/kem_r1_reference.py';inputs[p.relative_to(ROOT).as_posix()]=sha(p)
        write(output/'provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),input_sha256=inputs,
            output_sha256={p.name:sha(p) for p in output.iterdir() if p.is_file()}))
    else:
        manifest=read(output/'provenance.json')
        for group,base in [('input_sha256',ROOT),('output_sha256',output)]:
            for name,expected in manifest[group].items():
                if sha(base/name)!=expected:
                    raise ValueError(f'M02 checksum failed: {name}')
        with gzip.open(output/'mutations.jsonl.gz','rb') as stream:
            replay=mutations(stream,ref,args.limit)
        if args.limit is None and replay!=read(output/'mutations.json'):
            raise ValueError('mutation replay differs')
        if args.limit is not None and (args.limit<1 or replay['cases']!=min(args.limit,10000)):
            raise ValueError('mutation sample incomplete')
        with gzip.open(output/'timing.jsonl.gz','rt',encoding='utf-8') as stream:
            measured=timing_summary([json.loads(line) for line in stream])
        if measured!=read(output/'timing.json'):
            raise ValueError('timing arithmetic differs')
        result=dict(mutation_cases_replayed=replay['cases'],full_hashes_verified=True,
            timing_statistics_replayed=True,constant_time_proven=False)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
