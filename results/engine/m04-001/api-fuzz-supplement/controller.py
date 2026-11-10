"""Short, local robustness check of the project's own public API harness."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

root = Path('/mnt/c/Users/majax/Documents/Codex/NIST')
sys.path.insert(0, str(root / 'research'))
from run_m04_fuzz_smoke import run_target, save, sha

out = root / 'artifacts/generated/m04-fuzz-api-supplement'
if out.exists():
    raise ValueError('preserve existing evidence; select another run')
out.mkdir()
(out / 'source').mkdir()
(out / 'bin').mkdir()
parent = root / 'artifacts/generated/m04-fuzz-smoke'
expected = json.loads((parent / 'built-binaries.json').read_text())['binary_sha256']['api_sequence']
shutil.copyfile(parent / 'bin/api_sequence', out / 'bin/api_sequence')
(out / 'bin/api_sequence').chmod(0o700)
if sha(out / 'bin/api_sequence') != expected:
    raise ValueError('instrumented binary differs')
seeds = out / 'initial-corpus/api_sequence'
seeds.mkdir(parents=True)
for source in sorted((root / 'artifacts/generated/m03-seeds-final/api_sequence').iterdir()):
    shutil.copyfile(source, seeds / source.name)
if len(list(seeds.iterdir())) != 32:
    raise ValueError('exactly 32 final synthetic seeds required')
save(out / 'config.json', {'parent': str(parent), 'binary_sha256': expected,
    'seed_sha256': {p.name: sha(p) for p in sorted(seeds.iterdir())},
    'same_ASan_and_rebuilt_std_binary': True, 'minimum_CPU_seconds': 60,
    'purpose': 'Exercise mutation after initialization of the local public API test harness',
    'prior_auxiliary_agent': 'ended before preparing this supplement; no result credited'})
env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1')
result = run_target(3, out, env, 10, 60)
after = 0
for segment in result['segments']:
    log = out / 'api_sequence' / ('segment-%03d.log' % segment['segment'])
    matches = re.findall(r'#(\d+)\s+INITED', log.read_text(errors='replace'))
    if not matches:
        raise ValueError('initialization counter missing')
    after += segment['executions'] - int(matches[-1])
if after <= 0:
    raise ValueError('no execution after corpus initialization')
summary = {'results': {'api_sequence': result}, 'executions_after_initialization': after,
           'binary_sha256': expected, 'new_build_performed': False,
           'independent_oracle_replayed': False, 'line_coverage_measured': False,
           'initial_seeds': 32, 'seed_replays_included_in_CPU_time': True,
           'parent_smoke_preserved': True}
save(out / 'summary.json', summary)
print(json.dumps({'CPU_seconds': result['CPU_seconds'], 'executions_after_initialization': after}))
