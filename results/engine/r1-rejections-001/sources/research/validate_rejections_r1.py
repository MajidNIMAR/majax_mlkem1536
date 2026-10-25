"""Paired Rust/Python rejection corpus, using the frozen R1 independent oracle."""

import argparse
from datetime import datetime,timezone
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
DEFAULT=ROOT/'results/engine/r1-rejections-001'
PARENT=ROOT/'results/engine/r1-001'
SOURCES=['Cargo.toml','Cargo.lock','crates/kem1536/Cargo.toml','crates/kem1536-cli/Cargo.toml',
    'crates/kem1536/src/dev_kem.rs','crates/kem1536/src/reference_ring.rs',
    'crates/kem1536-cli/src/main.rs','research/validate_rejections_r1.py']


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def oracle():
    p=PARENT/'sources/research/kem_r1_reference.py'
    spec=importlib.util.spec_from_file_location('frozen_r1_rejections',p)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def check(stream,ref,limit):
    d,z,m=ref.synthetic_seeds(0)
    ek,dk=ref.keygen(d,z); base,_=ref.encapsulate(ek,m)
    count=0; digest=hashlib.sha256()
    for line in stream:
        if limit is not None and count>=limit:
            break
        row=json.loads(line)
        if set(row)!={'case','shared'} or row['case']!=count:
            raise ValueError('paired rejection order mismatch')
        bad=bytearray(base); bad[0]=255; bad[1]|=31
        bad[-8:]=count.to_bytes(8,'little')
        shared,accepted=ref.decapsulate(dk,bytes(bad))
        if accepted or shared!=ref.fallback(z,bytes(bad)) or shared!=bytes(row['shared']):
            raise ValueError(f'paired rejection mismatch at {count}')
        digest.update(bad); digest.update(shared)
        count+=1
    return count,digest.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate',action='store_true')
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--output',type=Path,default=DEFAULT)
    parser.add_argument('--limit',type=int)
    args=parser.parse_args()
    output=args.output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT or (args.limit is not None and not 1<=args.limit<=10000):
        raise ValueError('new local output and valid replay limit required')
    ref=oracle()
    start=time.perf_counter()
    if args.generate:
        if output.exists() or args.binary is None or args.limit is not None:
            raise ValueError('new output and explicit research binary required')
        binary=args.binary.resolve()
        if not binary.is_relative_to(ROOT):
            raise ValueError('local research build required')
        binary_hash=sha(binary)
        output.mkdir(parents=True)
        with (output/'rejections.jsonl.gz').open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed:
            with subprocess.Popen([str(binary),'dev-rejection-vectors'],stdout=subprocess.PIPE) as process:
                def rows():
                    for line in process.stdout:
                        compressed.write(line)
                        yield line
                try:
                    count,digest=check(rows(),ref,None)
                except BaseException:
                    process.terminate(); process.wait(); raise
                if process.wait()!=0 or count!=10000:
                    raise ValueError('paired rejection generation incomplete')
        original=json.loads((PARENT/'validation.json').read_text())['rejection_corpus']
        if digest!=original['ciphertext_and_replacement_sha256']:
            raise ValueError('paired corpus differs from original independent corpus')
        result=dict(profile='KEM1536-DEV-Q7681-R1',paired_rejections=count,
            accepted_in_independent_reference=0,all_replacement_secrets_equal=True,
            ciphertext_and_replacement_sha256=digest,synthetic_case0_key_only=True,
            elapsed_seconds=time.perf_counter()-start,security_validation='pending',j3_validated=False)
        (output/'validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
        inputs={}
        for name in SOURCES:
            copy=output/'sources'/name; copy.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,copy); inputs[copy.relative_to(ROOT).as_posix()]=sha(copy)
        for name in ('provenance.json','validation.json','sources/research/kem_r1_reference.py'):
            p=PARENT/name; inputs[p.relative_to(ROOT).as_posix()]=sha(p)
        provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),research_binary_sha256=binary_hash,
            input_sha256=inputs,output_sha256={n:sha(output/n) for n in ('rejections.jsonl.gz','validation.json')})
        (output/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8',newline='\n')
    else:
        manifest=json.loads((output/'provenance.json').read_text())
        for group,base in [('input_sha256',ROOT),('output_sha256',output)]:
            for name,expected in manifest[group].items():
                if sha(base/name)!=expected:
                    raise ValueError(f'paired rejection checksum mismatch: {name}')
        with gzip.open(output/'rejections.jsonl.gz','rb') as stream:
            count,digest=check(stream,ref,args.limit)
        saved=json.loads((output/'validation.json').read_text())
        if args.limit is None and (count!=10000 or digest!=saved['ciphertext_and_replacement_sha256']):
            raise ValueError('paired rejection full replay failed')
        if args.limit is not None and count!=args.limit:
            raise ValueError('paired rejection sample missing')
        result=dict(paired_rejections_replayed=count,total_frozen_rejections=10000,
            all_hashes_verified=True,all_replacement_secrets_equal=True,security_validation='pending')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
