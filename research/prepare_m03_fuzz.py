"""Build synthetic fixtures and new libFuzzer seed directories from frozen M01."""
import argparse,gzip,hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TARGETS=('import_public','import_private','decapsulate','api_sequence')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve()
    if not out.is_relative_to(ROOT/'artifacts/generated') or out.exists():
        raise ValueError('new generated corpus path required')
    rows=[]
    source=ROOT/'results/engine/r1-001/vectors.jsonl.gz'
    with gzip.open(source,'rt',encoding='utf-8') as stream:
        for line in stream:
            rows.append(json.loads(line))
            if len(rows)==16:break
    assert [v['case'] for v in rows]==list(range(16))
    fixture=b''.join(bytes(v[field]) for v in rows for field in ('ek','dk','ciphertext','shared'))
    assert len(fixture)==164864
    dest=ROOT/'fuzz/fixtures/cases.bin';dest.parent.mkdir(parents=True,exist_ok=True)
    if dest.exists() and dest.read_bytes()!=fixture:raise ValueError('synthetic fixtures changed')
    if not dest.exists():dest.write_bytes(fixture)
    for target in TARGETS:(out/target).mkdir(parents=True)
    def put(target,raw):
        (out/target/hashlib.sha256(raw).hexdigest()).write_bytes(raw)
    for i,v in enumerate(rows):
        put('import_public',bytes(v['ek']));put('import_private',bytes(v['dk']))
        put('decapsulate',bytes([i])+bytes(v['ciphertext']))
        put('decapsulate',bytes([i])+bytes(2656))
        raw=bytearray(v['ciphertext']);raw[0]=255;raw[1]|=31
        put('decapsulate',bytes([i])+raw)
        put('api_sequence',bytes([i])+b''.join(bytes([op,255,255,mask]) for op,mask in ((0,1),(1,1),(2,1),(3,0))))
        put('api_sequence',bytes([i,3,0,0,1]))
    for target,size in [('import_public',2528),('import_private',5088),('decapsulate',2657)]:
        for length in (0,1,size-64,size-1,size,size+1,size+64,16384):
            for byte in (0,255):put(target,bytes([byte])*length)
    manifest=dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        fixtures_sha256=hashlib.sha256(fixture).hexdigest(),synthetic_cases=16,
        seeds={target:{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((out/target).iterdir())} for target in TARGETS})
    (out/'seeds.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({target:len(values) for target,values in manifest['seeds'].items()}))

if __name__=='__main__':main()
