"""Data-only verification and one-time sealing of isolated NTT measurements."""
import argparse
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import statistics
import struct
import tarfile
ROOT = Path(__file__).resolve().parents[1]

def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def checked_members(path):
    result = {}
    total = 0
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if not member.isfile() or name.is_absolute() or '..' in name.parts or (str(name) != member.name) or (member.name in result) or (member.size > 32000000):
                raise ValueError('invalid or oversized archive member')
            total += member.size
            if total > 100000000:
                raise ValueError('archive expansion exceeds bound')
            stream = archive.extractfile(member)
            result[member.name] = stream.read()
    return result

def analyze(members):

    def read(name):
        return json.loads(members[name])
    prereg = read('preregistration.json')
    require(sha(members['protocol-before-candidate.md']) == prereg['protocol_sha256'], 'M09 poly evidence invariant failed at line 41')
    require(sha(members['controller-before-candidate.py']) == prereg['controller_sha256'], 'M09 poly evidence invariant failed at line 42')
    require(sha(members['baseline-source.json']) == prereg['baseline_manifest_sha256'], 'M09 poly evidence invariant failed at line 43')
    for label in ('baseline', 'candidate'):
        expected = read(label + '-source.json')['source_sha256']
        actual = {n.removeprefix(label + '-source/'): sha(raw) for n, raw in members.items() if n.startswith(label + '-source/')}
        require(actual == expected, 'M09 poly evidence invariant failed at line 48')
    base = read('baseline-source.json')['source_sha256']
    cand = read('candidate-source.json')['source_sha256']
    require(set(base) == set(cand), 'M09 poly evidence invariant failed at line 51')
    require({n for n in base if base[n] != cand[n]} == {'crates/kem1536/src/engine_poly.rs'}, 'M09 poly evidence invariant failed at line 52')
    machine = read('machine-review.json')
    require(machine['tables_public_bytes'] == 1020, 'public table byte budget')
    for record in machine['records']:
        host = record['host']
        name = f"candidate/{host}/micro" + ('.exe' if host == 'windows' else '')
        binary = members[name]
        require(sha(binary) == record['binary_sha256'], 'reviewed image changed')
        require(record['division_lines'] == [], 'division inventory differs')
        for table in record['tables']:
            words = [pow(table['root'], offset * 256 // (2 * (1 << stage)), 7681)
                     for stage in range(8) for offset in range(1 << stage)]
            encoded = struct.pack('<255H', *words)
            require(len(encoded) == table['bytes'] == 510, 'table length differs')
            require(sha(encoded) == table['sha256'], 'independent table exponents differ')
            require(binary.count(encoded) == 1, 'table must occur once in reviewed binary')
            require([binary.index(encoded)] == table['file_offsets'], 'table location differs')
    memory_count = 0
    memory_operations = ('noop', 'calibration_8192', 'calibration_32768', 'calibration_65536',
                         'keygen', 'encaps', 'decaps_valid', 'decaps_reject', 'import_public_valid',
                         'import_private_valid', 'import_public_noncanonical', 'import_private_hash',
                         'import_private_secret_first', 'import_private_secret_last', 'import_private_public',
                         'import_private_combined', 'import_public_short', 'import_private_short')
    for host in ('windows', 'linux'):
        prefix = f'baseline-memory/{host}/'
        build = read(prefix + 'build.json')
        run = read(prefix + 'run.json')
        raw = members[prefix + 'memory.jsonl']
        binary = members[prefix + 'probe' + ('.exe' if host == 'windows' else '')]
        require(sha(binary) == build['binary_sha256'] == run['binary_sha256'], 'baseline memory image differs')
        require(build['source_manifest_sha256'] == sha(members['baseline-source.json']), 'baseline memory source differs')
        require(run['exit_code'] == 0 and run['repetitions'] == 3, 'baseline memory execution failed')
        require(sha(raw) == run['raw_sha256'], 'baseline memory raw hash differs')
        rows = [json.loads(line) for line in raw.splitlines()]
        grid = {(op, pattern, sample) for op in memory_operations for pattern in (0xa5, 0x5a) for sample in range(3)}
        require(len(rows) == len(grid), 'baseline memory grid size differs')
        require({(r['operation'], r['paint_pattern'], r['sample']) for r in rows} == grid, 'baseline memory grid differs')
        require(all(r['functional_validation'] is True and r['saturated'] is False for r in rows), 'baseline memory calibration/function failed')
        memory_count += len(rows)
    summary, count = ({}, 0)
    for host in ('windows', 'linux'):
        records = read(f'paired-001-{host}-runs.json')
        require(len(records) == 20, 'M09 poly evidence invariant failed at line 56')
        groups, identities = ({}, set())
        for record in records:
            label, kind, series = (record['label'], record['kind'], record['series'])
            require(record['host'] == host and label in ('baseline', 'candidate') and (kind in ('micro', 'kem')), 'M09 poly evidence invariant failed at line 60')
            require(type(series) is int and 0 <= series < 5, 'M09 poly evidence invariant failed at line 61')
            identity = (label, kind, series)
            require(identity not in identities, 'M09 poly evidence invariant failed at line 63')
            identities.add(identity)
            binary = read(f'{label}/{host}/build.json')[kind]
            require(sha(members[binary['binary']]) == binary['sha256'] == record['binary_sha256'], 'M09 poly evidence invariant failed at line 66')
            require(record['exit_code'] == 0, 'M09 poly evidence invariant failed at line 67')
            require(sha(members[record['raw']]) == record['raw_sha256'], 'M09 poly evidence invariant failed at line 68')
            rows = [json.loads(line) for line in members[record['raw']].splitlines()]
            operations = ('forward', 'inverse', 'multiply_add') if kind == 'micro' else ('keygen', 'encaps', 'decaps_valid', 'decaps_rejected')
            samples = 500 if kind == 'micro' else 250
            require(len(rows) == samples * len(operations), 'M09 poly evidence invariant failed at line 72')
            require({(r['operation'], r['iteration']) for r in rows} == {(op, i) for op in operations for i in range(samples)}, 'M09 poly evidence invariant failed at line 73')
            for row in rows:
                require(row['series'] == series and type(row['nanoseconds']) is int and (row['nanoseconds'] > 0), 'M09 poly evidence invariant failed at line 75')
                batch = row.get('batch', 1)
                require(batch == (32 if kind == 'micro' else 1), 'M09 poly evidence invariant failed at line 77')
                groups.setdefault((label, row['operation']), []).append(row['nanoseconds'] / batch)
            count += len(rows)
        require(identities == {(label, kind, series) for label in ('baseline', 'candidate') for kind in ('micro', 'kem') for series in range(5)}, 'M09 poly evidence invariant failed at line 80')
        panels = {}
        for (label, operation), values in groups.items():
            values.sort()
            panels.setdefault(operation, {})[label] = {'count': len(values), 'median_ns': statistics.median(values), 'p95_ns': values[math.ceil(0.95 * len(values)) - 1]}
        for op, panel in panels.items():
            ratios = {n: panel['candidate'][n] / panel['baseline'][n] for n in ('median_ns', 'p95_ns')}
            limits = (0.9, 1.2) if op in ('forward', 'inverse') else (1.1, 1.25) if op == 'multiply_add' else (1.05, 1.2)
            panel['ratios'] = ratios
            panel['budget_passed'] = ratios['median_ns'] <= limits[0] and ratios['p95_ns'] <= limits[1]
        summary[host] = panels
    require(summary == read('paired-001-summary.json'), 'M09 poly evidence invariant failed at line 93')
    failures = [f'{host}/{op}' for host, panels in summary.items() for op, panel in panels.items() if not panel['budget_passed']]
    return {'observations': count, 'baseline_memory_observations': memory_count,
            'all_latency_budgets_passed': not failures, 'failed_panels': failures, 'summary': summary}

def freeze(output, source):
    output.mkdir(parents=True, exist_ok=False)
    paths = sorted((p for p in source.rglob('*') if p.is_file()))
    hashes = {p.relative_to(source).as_posix(): sha(p.read_bytes()) for p in paths}
    with tarfile.open(output / 'acquisition.tar.gz', 'x:gz', compresslevel=6) as archive:
        for p in paths:
            archive.add(p, arcname=p.relative_to(source).as_posix(), recursive=False)
    members = checked_members(output / 'acquisition.tar.gz')
    require({n: sha(raw) for n, raw in members.items()} == hashes, 'M09 poly evidence invariant failed at line 107')
    result = analyze(members)
    (output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    provenance = {'schema': 1, 'archive_sha256': sha((output / 'acquisition.tar.gz').read_bytes()), 'members': hashes, 'verification_sha256': sha((output / 'verification.json').read_bytes()), 'scope': 'isolated engine_poly change; not the complete final M09 source'}
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')

def verify(output):
    provenance = json.loads((output / 'provenance.json').read_text())
    require(sha((output / 'acquisition.tar.gz').read_bytes()) == provenance['archive_sha256'], 'M09 poly evidence invariant failed at line 118')
    members = checked_members(output / 'acquisition.tar.gz')
    require({n: sha(raw) for n, raw in members.items()} == provenance['members'], 'M09 poly evidence invariant failed at line 120')
    result = analyze(members)
    require(sha((output / 'verification.json').read_bytes()) == provenance['verification_sha256'], 'M09 poly evidence invariant failed at line 122')
    require(result == json.loads((output / 'verification.json').read_text()), 'M09 poly evidence invariant failed at line 123')
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('freeze', 'verify'))
    parser.add_argument('--output', type=Path, default=ROOT / 'results/engine/m09-poly-001')
    args = parser.parse_args()
    if args.action == 'freeze':
        freeze(args.output, ROOT / 'artifacts/generated/m09-poly-001')
    result = verify(args.output)
    print(json.dumps({k: v for k, v in result.items() if k != 'summary'}))
if __name__ == '__main__':
    main()
