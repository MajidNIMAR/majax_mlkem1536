"""Generate/replay public R1 vectors against the independent Python engine."""

import argparse
from datetime import datetime,timezone
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import shutil
import time

import numpy as np
import kem_r1_reference as ref

ROOT=Path(__file__).resolve().parents[1]
DEFAULT=ROOT/'results/engine/r1-001'
INPUTS=['docs/SPECIFICATION_DEV_Q7681_R1.md','docs/BILAN_J2_ET_DECISION_PROTOTYPE.md',
    'Cargo.toml','Cargo.lock','crates/kem1536/Cargo.toml','crates/kem1536-cli/Cargo.toml',
    'crates/kem1536/src/lib.rs','crates/kem1536/src/dev_kem.rs','crates/kem1536/src/reference_ring.rs',
    'crates/kem1536-cli/src/main.rs','crates/kem1536-cli/tests/commands.rs',
    'research/kem_r1_reference.py','research/validate_engine_r1.py','research/test_kem_r1_reference.py',
    'research/requirements-cbd-dimensions.txt']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(row,index):
    if row['case']!=index:
        raise ValueError('case order mismatch')
    d,z,m=ref.synthetic_seeds(index)
    ek,dk=ref.keygen(d,z)
    c,k=ref.encapsulate(ek,m)
    got,accepted=ref.decapsulate(dk,c)
    if not accepted or got!=k:
        raise ValueError('independent honest roundtrip failed')
    bad=bytearray(c); bad[0]=255; bad[1]|=31
    rejected,accepted=ref.decapsulate(dk,bytes(bad))
    if accepted or rejected!=ref.fallback(z,bytes(bad)):
        raise ValueError('independent rejection oracle failed')
    expanded=ref.g(b'KG',d,b'\x06')
    expected=dict(case=index,d=d,z=z,m=m,ek=ek,dk=dk,ciphertext=c,shared=k,rejected_shared=rejected,
        rho=expanded[:32],sigma=expanded[32:],a00=ref.pack(ref.uniform(expanded[:32],0,0),13))
    if set(row)!=set(expected):
        raise ValueError('vector fields mismatch')
    for name,value in expected.items():
        if name!='case' and bytes(row[name])!=value:
            raise ValueError(f'Rust/Python mismatch: case {index}, field {name}')


def rejection_corpus(count=10000):
    d,z,m=ref.synthetic_seeds(0)
    ek,dk=ref.keygen(d,z); c,_=ref.encapsulate(ek,m)
    digest=hashlib.sha256()
    for i in range(count):
        bad=bytearray(c); bad[0]=255; bad[1]|=31
        bad[-8:]=i.to_bytes(8,'little')
        got,accepted=ref.decapsulate(dk,bytes(bad))
        if accepted or got!=ref.fallback(z,bytes(bad)):
            raise ValueError('independent rejection corpus failed')
        digest.update(bad); digest.update(got)
    return dict(cases=count,oracle='Python decrypt/derive/re-encrypt comparison',
        canonical_failure_established=True,ciphertext_and_replacement_sha256=digest.hexdigest())


def main():
    global ref
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate',action='store_true')
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--output',type=Path,default=DEFAULT)
    parser.add_argument('--limit',type=int)
    args=parser.parse_args()
    if np.__version__!='2.3.5':
        raise RuntimeError('pinned NumPy 2.3.5 required')
    output=args.output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT:
        raise ValueError('output below NIST required')
    start=time.perf_counter()
    if args.generate:
        if output.exists() or args.binary is None or args.limit is not None:
            raise ValueError('new output, explicit research binary and full generation required')
        binary=args.binary.resolve()
        if not binary.is_relative_to(ROOT):
            raise ValueError('local research build required')
        binary_digest=sha(binary)
        output.mkdir(parents=True)
        count=0
        # Binary stdout is captured directly; no shell encoding or key output in logs.
        with (output/'vectors.jsonl.gz').open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed:
            with subprocess.Popen([str(binary),'dev-vectors','1000'],stdout=subprocess.PIPE) as process:
                try:
                    for line in process.stdout:
                        validate(json.loads(line),count)
                        compressed.write(line)
                        count+=1
                        if count%100==0:
                            print(f'{count}/1000 independent vector comparisons',flush=True)
                except BaseException:
                    process.terminate(); process.wait(); raise
                if process.wait()!=0 or count!=1000:
                    raise ValueError('Rust generation incomplete')
        corpus=rejection_corpus()
        result=dict(profile='KEM1536-DEV-Q7681-R1',synthetic_public_test_data=True,
            vectors_verified=count,fields_per_vector=12,independent_arithmetic='NumPy integer convolution',
            full_byte_agreement=True,rejection_corpus=corpus,python=platform.python_version(),numpy=np.__version__,
            generation_and_independent_validation_seconds=time.perf_counter()-start,
            security_validation='pending',j2_closed=False,j3_validated=False)
        (output/'validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
        archived={}
        for name in INPUTS:
            copy=output/'sources'/name
            copy.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,copy)
            archived[copy.relative_to(ROOT).as_posix()]=sha(copy)
        provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),specification_commit='e325f50',
            source_layout='frozen copies permit subsequent engine development',
            research_binary_sha256=binary_digest,input_sha256=archived,
            output_sha256={n:sha(output/n) for n in ('vectors.jsonl.gz','validation.json')})
        (output/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8',newline='\n')
    else:
        provenance=json.loads((output/'provenance.json').read_text(encoding='utf-8'))
        for group,base in [('input_sha256',ROOT),('output_sha256',output)]:
            for name,expected in provenance[group].items():
                if sha(base/name)!=expected:
                    raise ValueError(f'R1 provenance mismatch: {name}')
        frozen=output/'sources/research/kem_r1_reference.py'
        spec=importlib.util.spec_from_file_location('r1_frozen_oracle',frozen)
        ref=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ref)
        count=0
        with gzip.open(output/'vectors.jsonl.gz','rt',encoding='utf-8') as stream:
            for index,line in enumerate(stream):
                if args.limit is not None and count>=args.limit:
                    break
                validate(json.loads(line),index)
                count+=1
        saved=json.loads((output/'validation.json').read_text(encoding='utf-8'))
        if args.limit is None:
            if count!=1000 or rejection_corpus()!=saved['rejection_corpus']:
                raise ValueError('R1 full replay differs')
        elif args.limit<1 or count!=min(args.limit,1000):
            raise ValueError('R1 smoke replay incomplete')
        result=dict(profile='KEM1536-DEV-Q7681-R1',vectors_verified=count,total_frozen_vectors=1000,
            full_rejection_corpus_replayed=args.limit is None,all_hashes_verified=True,
            security_validation='pending',j2_closed=False,j3_validated=False)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
