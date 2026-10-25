"""Confront retained deterministic fuzz inputs with frozen Python and Rust."""
import argparse,hashlib,importlib.util,json,subprocess
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
TARGETS=('import_public','import_private','decapsulate','api_sequence')
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--campaign',type=Path,required=True)
    args=parser.parse_args();campaign=args.campaign.resolve()
    path=campaign/'source/oracle/kem_r1_reference.py'
    spec=importlib.util.spec_from_file_location('m03_frozen_oracle',path);ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
    if ref.np.__version__!='2.3.5':raise ValueError('pinned NumPy 2.3.5 required')
    fixtures=(campaign/'source/fuzz/fixtures/cases.bin').read_bytes()
    records=[fixtures[i*10304:(i+1)*10304] for i in range(16)]
    counts={name:0 for name in TARGETS};requests={};fresh=0
    def add(kind,key,raw):
        identity=(kind,key,raw)
        requests[identity]=dict(kind=kind,key=key,raw=list(raw))
    for name in TARGETS:
        for path in sorted((campaign/name/'corpus').iterdir()):
            data=path.read_bytes();counts[name]+=1
            if name=='import_public':add('public',0,data)
            elif name=='import_private':add('private',0,data)
            elif name=='decapsulate' and data:add('ciphertext',data[0]%16,data[1:])
            elif name=='api_sequence' and data:
                key=data[0]%16;record=records[key]
                for i in range(1,min(len(data),65),4):
                    step=data[i:i+4]
                    if len(step)!=4:break
                    op=step[0]%4;offset=int.from_bytes(step[1:3],'little')
                    if op==3:fresh+=1;continue
                    kind,raw=[('public',record[:2528]),('private',record[2528:7616]),('ciphertext',record[7616:10272])][op]
                    altered=bytearray(raw);altered[offset%len(raw)]^=step[3];add(kind,key,bytes(altered))
    matched=0;canonical_reference_acceptances=0;digest=hashlib.sha256()
    binary=campaign/'bin/m03-replay.exe'
    with subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as p:
        try:
            for identity,request in requests.items():
                kind,key,raw=identity
                p.stdin.write((json.dumps(request,separators=(',',':'))+'\n').encode());p.stdin.flush()
                actual=json.loads(p.stdout.readline())
                expected={'accepted':False}
                if kind in ('public','private'):
                    try:(ref.public if kind=='public' else ref.private)(raw);expected={'accepted':True}
                    except ValueError:pass
                elif len(raw)==2656:
                    shared,accepted=ref.decapsulate(records[key][2528:7616],raw)
                    canonical_reference_acceptances+=int(accepted)
                    expected=dict(accepted=True,shared=list(shared))
                if actual!=expected:raise ValueError(f'frozen Python/Rust mismatch in {kind}, key {key}')
                digest.update(json.dumps([request,actual],sort_keys=True,separators=(',',':')).encode());matched+=1
            p.stdin.close()
            if p.wait(timeout=60)!=0:raise ValueError('Rust corpus replay failed')
        except BaseException:p.kill();p.wait();raise
    result=dict(corpus_files=counts,distinct_deterministic_requests=matched,all_Rust_Python_outputs_equal=True,
        oracle_acceptances_among_ciphertext_requests=canonical_reference_acceptances,
        fresh_random_operations_checked_by_fuzzer_but_not_reproduced_by_seed=fresh,
        cumulative_sha256=digest.hexdigest(),numpy=ref.np.__version__,replay_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (campaign/'oracle-replay.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
