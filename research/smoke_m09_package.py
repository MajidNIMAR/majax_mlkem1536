"""Run the qualified original M09 CLI and default consumer on the native CI OS.

This is a new finite integration check of preserved bytes, without rebuilding,
benchmarking, fuzzing, disassembly or an external-audit/constant-time claim.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile

from archive_m09 import ROOT, members, read, require, sha
from smoke_m08_package import (native_host, check_architecture, json_result, check_cli_test,
                              check_consumer_smoke, check_consumer_exhaustive, run_process)


def recover(snapshot, group):
    provenance = read(snapshot / 'provenance.json')
    entry = provenance['groups'][group]
    path = snapshot / entry['archive']
    require(path.resolve().parent == snapshot.resolve() and sha(path) == entry['archive_sha256'],
            'qualified stage archive differs')
    result = members(path)
    require({name: {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for name, raw in result.items()}
            == entry['files'], 'qualified stage members differ')
    return result


def smoke(snapshot):
    host = native_host()
    snapshot = Path(snapshot).resolve()
    source = recover(snapshot, 'qualification')
    distribution = recover(snapshot, 'distribution')
    build = json.loads(source[host+'/build.json'])
    result = json.loads(distribution['result.json'])
    require(result['promotion_status'] == 'QUALIFIED_INTERNAL', 'original M09 was not qualified internally')
    require(build['source_manifest_sha256'] == hashlib.sha256(source['source.json']).hexdigest()
            == result['source_manifest_sha256'], 'CLI/consumer source binding differs')
    suffix = '.exe' if host == 'windows' else ''
    cli_raw = distribution[host+'/package/bin/kem1536'+suffix]
    consumer_raw = source[build['binaries']['consumer']['path']]
    cli_hash, consumer_hash = (hashlib.sha256(raw).hexdigest() for raw in (cli_raw, consumer_raw))
    require(cli_hash == build['binaries']['delivered']['sha256']
            and consumer_hash == build['binaries']['consumer']['sha256'], 'preserved original image differs')
    parent = ROOT / 'target/m09-native-smoke'
    require(parent.resolve().is_relative_to(ROOT.resolve()), 'native temporary parent escapes NIST')
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='native-', dir=parent) as temporary:
        directory = Path(temporary)
        require(directory.resolve().parent == parent.resolve(), 'native directory escapes owned parent')
        cli, consumer = directory/('kem1536'+suffix), directory/('consumer'+suffix)
        for path, raw in ((cli, cli_raw), (consumer, consumer_raw)):
            path.write_bytes(raw)
            check_architecture(path, host)
            if host == 'linux':
                path.chmod(0o700)
        checks = []
        value, receipt = json_result(cli, 'dev-self-test', 120)
        check_cli_test(value)
        checks.append(receipt)
        for args in (['dev-vectors','1'], ['dev-rejection-vectors'], ['dev-hardening'], ['dev-mutations'], ['dev-timing']):
            process = run_process(cli, args, 120)
            require(process.returncode == 1 and process.stdout == b'', 'research command exposed by default CLI')
            checks.append({'operation': args, 'exit_code': process.returncode})
        value, receipt = json_result(consumer, 'smoke', 120)
        check_consumer_smoke(value, host)
        checks.append(receipt)
        value, receipt = json_result(consumer, 'exhaustive', 180)
        check_consumer_exhaustive(value)
        checks.append(receipt)
    return {'schema':'m09-native-smoke-v1', 'host':host, 'finished_utc':datetime.now(timezone.utc).isoformat(),
        'source_manifest_sha256':build['source_manifest_sha256'], 'original_CLI_sha256':cli_hash,
        'original_default_consumer_sha256':consumer_hash, 'checks':checks, 'fresh_round_trips':16,
        'implicit_rejections':16, 'consumer_cases':13, 'exhaustive_probes':88576,
        'new_builds':0, 'fresh_fuzzing_credit_seconds':0, 'constant_time_proved':False, 'external_audit':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,default=ROOT/'results/engine/m09-001')
    args = parser.parse_args()
    print(json.dumps(smoke(args.snapshot),indent=2))


if __name__ == '__main__':
    main()
