"""Replay P01 arithmetic and binary inventories, verify M03 and smoke evidence."""
import gzip,hashlib,json,tarfile
from pathlib import Path
from inspect_m03_binary import parse_disassembly,resolve_elf_relocations,inventory
from summarize_m03_bench import summarize

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/engine/m03-001'
SMOKE=ROOT/'results/engine/m03-smoke-001'
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def hashes(run):
    manifest=read(run/'provenance.json');count=0
    for key,base in [('input_sha256',ROOT),('output_sha256',run)]:
        for name,expected in manifest[key].items():
            if sha(base/name)!=expected:raise ValueError('M03 checksum: '+name)
            count+=1
    return count

def main():
    count=hashes(RUN)+hashes(SMOKE)
    for platform in ('windows','linux'):
        with gzip.open(RUN/f'bench/{platform}-observations.jsonl.gz','rt',encoding='utf-8') as f:
            computed=summarize([json.loads(line) for line in f])
        saved=read(RUN/f'bench/{platform}-summary.json')
        if any(saved[key]!=value for key,value in computed.items()):raise ValueError('P01 arithmetic mismatch')
        folder=RUN/'audit'/platform
        with gzip.open(folder/'binary.gz','rb') as stream:binary=stream.read()
        saved=read(folder/'summary.json')
        if hashlib.sha256(binary).hexdigest()!=saved['binary_sha256'] or len(binary)!=saved['binary_size']:
            raise ValueError('archived release binary differs')
        with gzip.open(folder/'disassembly.txt.gz','rt',encoding='utf-8') as stream:
            functions=parse_disassembly(stream.read())
        if (folder/'relocations.txt').exists():resolve_elf_relocations(functions,(folder/'relocations.txt').read_text())
        computed=inventory(functions)
        if any(saved[key]!=value for key,value in computed.items()):raise ValueError('binary inventory mismatch')
    smoke=read(SMOKE/'summary.json')
    if not smoke['all_budgets_reached'] or smoke['T07_duration_reached'] or smoke['T07_validated']:
        raise ValueError('short campaign must not claim T07')
    if smoke['automatic_postprocessing']!=dict(coverage_exported=True,independent_corpus_replayed=True):
        raise ValueError('short pipeline incomplete')
    with tarfile.open(SMOKE/'campaign.tar.gz','r:gz') as archive:
        for name,expected in smoke['source_sha256'].items():
            content=archive.extractfile('source/'+name).read()
            if hashlib.sha256(content).hexdigest()!=expected:raise ValueError('smoke source differs')
        oracle=json.load(archive.extractfile('oracle-replay.json'))
        if not oracle['all_Rust_Python_outputs_equal'] or oracle['distinct_deterministic_requests']!=511:
            raise ValueError('smoke independent replay incomplete')
        coverage=json.load(archive.extractfile('coverage-summary.json'))
        if set(coverage)!=set(('import_public','import_private','decapsulate','api_sequence')):
            raise ValueError('coverage target missing')
        for target,files in coverage.items():
            if not files:raise ValueError('R1 coverage absent in '+target)
            for file in files:
                for metric in file['summary'].values():
                    if not 0<=metric['covered']<=metric['count']:raise ValueError('invalid coverage counts')
    print(json.dumps(dict(snapshot='m03-001',hashes_verified=count,benchmark_observations_recomputed=60000,
        full_binary_inventories_recomputed=2,smoke_corpus_requests_previously_verified=511,
        long_campaign_closed=False,constant_time_proven=False,M03_A01_resolved=False),indent=2))

if __name__=='__main__':main()
