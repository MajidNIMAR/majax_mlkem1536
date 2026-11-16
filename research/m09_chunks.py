"""Byte-preserving publication chunks for the already verified M09 capsule.

This adapter changes storage only. The original archive and engine provenance
hashes remain the scientific identities; no acquisition or engine is executed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil

from export_publication import safe_name

ROOT = Path(__file__).resolve().parents[1]
PART_LIMIT = 90*1024*1024
TOTAL_LIMIT = 512*1024*1024


def require(condition,message):
    if not condition:
        raise ValueError(message)


def ordinary_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while raw := stream.read(1024*1024):
            h.update(raw)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def recovered_bytes(path):
    path = Path(path)
    descriptor = read(path.parent/'archive-parts.json')
    require(descriptor['schema']=='m09-byte-identical-parts-v1','unknown chunk descriptor')
    record = descriptor['archives'][path.name]
    parts = record['parts']
    require(type(parts) is list and 1 <= len(parts) <= 32
            and type(record['bytes']) is int and 0 < record['bytes'] <= TOTAL_LIMIT,'chunk count/size budget')
    result, names = bytearray(), set()
    for part in parts:
        name = part['name']
        safe_name(name)
        require('/' not in name and name.casefold() not in names,'chunk alias or path')
        names.add(name.casefold())
        require(type(part['bytes']) is int and 0 < part['bytes'] <= PART_LIMIT,'chunk byte budget')
        current = path.parent/name
        require(not current.is_symlink() and current.resolve().parent==path.parent.resolve()
                and current.stat().st_size==part['bytes'],'chunk file/type/size differs')
        raw = current.read_bytes()
        require(hashlib.sha256(raw).hexdigest()==part['sha256'],'chunk bytes differ')
        result.extend(raw)
        require(len(result)<=TOTAL_LIMIT,'chunk expansion exceeds budget')
    require(len(result)==record['bytes'] and hashlib.sha256(result).hexdigest()==record['sha256'],
            'joined archive differs from original')
    return bytes(result)


def open_archive(path):
    path = Path(path)
    return path.open('rb') if path.is_file() else io.BytesIO(recovered_bytes(path))


def sha(path):
    path = Path(path)
    if path.is_file():
        return ordinary_sha(path)
    return hashlib.sha256(recovered_bytes(path)).hexdigest()


def split(capsule):
    capsule = Path(capsule).resolve()
    require(capsule==ROOT/'results/engine/m09-001','exact verified M09 capsule required')
    provenance_sha = ordinary_sha(capsule/'provenance.json')
    provenance = read(capsule/'provenance.json')
    backup = ROOT/'artifacts/generated/m09-chunking-001'
    require(not backup.exists() and not (capsule/'archive-parts.json').exists(),'new packaging adaptation required')
    backup.mkdir()
    require(backup.resolve().parent==(ROOT/'artifacts/generated').resolve(),'backup outside owned parent')
    archives = {}
    for record in provenance['groups'].values():
        original = capsule/record['archive']
        if original.stat().st_size <= PART_LIMIT:
            continue
        require(not original.is_symlink() and original.resolve().parent==capsule.resolve()
                and ordinary_sha(original)==record['archive_sha256'],'original archive differs')
        parts = []
        with original.open('rb') as stream:
            index = 1
            while raw := stream.read(PART_LIMIT):
                name = original.name+f'.part-{index:03d}'
                with (capsule/name).open('xb') as target:
                    target.write(raw)
                parts.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
                index += 1
        archives[original.name] = {'bytes':original.stat().st_size,'sha256':record['archive_sha256'],'parts':parts}
    require(archives,'no oversized archive to split')
    descriptor = {'schema':'m09-byte-identical-parts-v1','engine_provenance_sha256':provenance_sha,
                  'part_limit_bytes':PART_LIMIT,'archives':archives,'new_acquisitions':0}
    (capsule/'archive-parts.json').write_text(json.dumps(descriptor,indent=2)+'\n',encoding='utf-8')
    for name, record in archives.items():
        require(hashlib.sha256(recovered_bytes(capsule/name)).hexdigest()==record['sha256'],'chunk roundtrip failed')
        original = capsule/name
        destination = backup/name
        require(original.resolve().parent==capsule.resolve() and destination.resolve().parent==backup.resolve(),
                'archive move escaped verified directories')
        original.rename(destination)
    output = ROOT/'results/engine/m09-chunks-001'
    require(not output.exists(),'new chunk-control capsule required')
    output.mkdir()
    shutil.copyfile(capsule/'archive-parts.json',output/'archive-parts.json')
    for name in ('m09_chunks.py','archive_m09.py'):
        shutil.copyfile(ROOT/'research'/name,output/name)
    (output/'README.md').write_text('# M09 archive publication parts\n\nStorage-only adaptation after the original full capsule replay. Join parts in descriptor order to recover the original archive SHA; engine provenance and all payload bytes are unchanged. The original frozen readers remain in controls.tar.gz; overlay these two adapter readers for direct chunk-aware replay, or reconstruct the single archive first. No engine, compiler or acquisition is rerun.\n',encoding='utf-8')
    meta = {'schema':'m09-chunk-controls-v1','engine_provenance_sha256':provenance_sha,
            'output_sha256':{p.name:ordinary_sha(p) for p in output.iterdir() if p.is_file()},
            'scientific_payload_bytes_changed':False,'new_acquisitions':0}
    (output/'provenance.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
    require(ordinary_sha(capsule/'provenance.json')==provenance_sha,'engine provenance changed')
    return verify(capsule)


def verify(capsule):
    capsule = Path(capsule)
    descriptor = read(capsule/'archive-parts.json')
    controls = ROOT/'results/engine/m09-chunks-001'
    provenance = read(controls/'provenance.json')
    require(provenance['schema']=='m09-chunk-controls-v1'
            and provenance['scientific_payload_bytes_changed'] is False and provenance['new_acquisitions']==0,
            'chunk scope differs')
    require({p.name:ordinary_sha(p) for p in controls.iterdir() if p.is_file() and p.name!='provenance.json'}
            ==provenance['output_sha256'],'chunk controls changed')
    require(ordinary_sha(capsule/'archive-parts.json')==ordinary_sha(controls/'archive-parts.json')
            and ordinary_sha(capsule/'provenance.json')==descriptor['engine_provenance_sha256']
            ==provenance['engine_provenance_sha256'],'chunk/engine binding differs')
    engine = read(capsule/'provenance.json')
    originals = {row['archive']:row['archive_sha256'] for row in engine['groups'].values()}
    for name, record in descriptor['archives'].items():
        require(originals.get(name)==record['sha256']
                and hashlib.sha256(recovered_bytes(capsule/name)).hexdigest()==record['sha256'],
                'original logical archive identity differs')
    return {'chunked_archives':len(descriptor['archives']),'scientific_payload_bytes_changed':False,
            'new_acquisitions':0,'engine_provenance_unchanged':True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('split','verify'))
    parser.add_argument('--capsule',type=Path,default=ROOT/'results/engine/m09-001')
    args = parser.parse_args()
    print(json.dumps(split(args.capsule) if args.action=='split' else verify(args.capsule),indent=2))


if __name__=='__main__':
    main()
