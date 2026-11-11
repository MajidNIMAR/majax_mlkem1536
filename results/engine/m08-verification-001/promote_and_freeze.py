"""Seal successful local M08 integration and promote the original Windows CLI."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).parent))
import capture_full_check

sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
read = lambda path: json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    check = ROOT / 'artifacts/generated/m08-code-checks-001/windows-001'
    checked = capture_full_check.verify(check)
    assert checked['exit_code'] == checked['effective_exit_code'] == 0
    native = ROOT / 'artifacts/generated/m08-native-001'
    assert read(native / 'command.json')['exit_code'] == 0
    live = read(native / 'stdout.json')
    assert live['CLI_fresh_round_trips'] == 16 and live['CLI_implicit_rejections_checked'] == 16
    assert live['consumer_single_coefficient_and_boundary_probes'] == 88576
    original = ROOT / 'artifacts/generated/m08-delivery-001/windows/package/bin/kem1536.exe'
    expected = 'd3fb7537face2cd4b7e295ec829b6a282a711d005f4535ff99dddce90a98dde1'
    assert sha(original) == expected == live['original_CLI_sha256']
    output = ROOT / 'results/engine/m08-verification-001'
    assert output.parent.resolve() == ROOT / 'results/engine' and not output.exists()
    output.mkdir()
    for path in check.iterdir():
        assert path.is_file()
        shutil.copyfile(path, output / path.name)
    for old, new in [('stdout.json', 'native-windows.stdout.json'), ('stderr.log', 'native-windows.stderr.log'),
                     ('command.json', 'native-command.json')]:
        shutil.copyfile(native / old, output / new)
    for suffix in ('stdout', 'stderr'):
        shutil.copyfile(check.parent / ('windows-001.verify.' + suffix), output / ('check-replay.' + suffix))
    for name in ('stdout.log', 'stderr.log', 'request.json', 'result.json'):
        shutil.copyfile(ROOT / 'artifacts/generated/m08-freeze-001' / name, output / ('freeze-' + name))
    shutil.copyfile(Path(__file__), output / 'promote_and_freeze.py')
    destination = ROOT / 'target/release/kem1536.exe'
    assert destination.parent.resolve() == ROOT / 'target/release'
    assert not destination.is_symlink() and not getattr(destination.lstat(), 'st_file_attributes', 0) & 0x400
    previous = sha(destination) if destination.exists() else None
    descriptor, name = tempfile.mkstemp(prefix='m08-canonical-', suffix='.exe', dir=destination.parent)
    os.close(descriptor)
    temporary = Path(name).resolve()
    assert temporary.parent == destination.parent.resolve()
    shutil.copyfile(original, temporary)
    assert sha(temporary) == expected
    os.replace(temporary, destination)
    assert sha(destination) == expected
    command = [str(destination), 'dev-self-test']
    with (output / 'canonical-self-test.stdout').open('xb') as stdout, (output / 'canonical-self-test.stderr').open('xb') as stderr:
        result = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr, timeout=120)
    value = read(output / 'canonical-self-test.stdout')
    assert result.returncode == 0 and value['fresh_round_trips'] == value['implicit_rejections_checked'] == 16
    assert value['secrets_printed'] is False and sha(destination) == expected
    receipt = {'profile': 'KEM1536-DEV-Q7681-R1', 'recorded_utc': datetime.now(timezone.utc).isoformat(),
               'canonical_path': str(destination), 'previous_sha256': previous, 'binary_sha256': expected,
               'source_original': str(original), 'command': command, 'exit_code': result.returncode,
               'new_compilation_performed': False, 'archived_M07_not_modified': True}
    (output / 'canonical-windows.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
    (output / 'README.md').write_text('# M08 local Windows integration\n\n'
        'The full scripts/dev.ps1 check passed with 352 Python tests, Rust tests, fmt, strict Clippy and all frozen evidence replays.\n'
        'The capture retains complete maintained file and tool inventories before/after and verifies equality.\n'
        'Separate native execution checks the original archived CLI (16/16 plus five normal research-command refusals)\n'
        'and the default-feature import consumer (fresh exchange/rejection and 88576 bounded probes).\n'
        'The canonical target/release/kem1536.exe is the original inventoried M08 Windows image, freshly self-tested after copying.\n'
        'These integration checks are not new benchmarks, fuzz campaigns or disassembly, and do not establish global security.\n', encoding='utf-8')
    manifest = {'schema': 1, 'scope': 'M08 complete local Windows check, native original images and canonical CLI',
                'output_sha256': {p.name: sha(p) for p in sorted(output.iterdir())}}
    (output / 'provenance.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    assert all(sha(output / name) == checksum for name, checksum in manifest['output_sha256'].items())
    print(json.dumps({'verification_files': len(manifest['output_sha256'])+1, 'canonical_sha256': expected,
                      'local_full_check': checked}, indent=2))


if __name__ == '__main__':
    main()
