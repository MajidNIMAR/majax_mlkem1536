"""Local M09 publication bookkeeping; no builds, acquisitions or network access."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import shutil
import sys
import re
import zipfile
import subprocess

ROOT = Path(r'C:\Users\majax\Documents\Codex\NIST')
BASE = ROOT / 'artifacts/generated/publication/m09-ci-001'
FINAL_RUN = 43806407492
PUBLIC = 'fdd323dcf840b0d12fd43a446acffbd0cce83d7b'
SOURCE = 'd616912fddd1e303c171678d0c6690286b570d38'

def sha(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()

def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')

def initial():
    source = BASE / '43804190038'
    output = ROOT / 'results/publication/r6-m09-initial-001'
    if output.exists():
        raise ValueError('new initial receipt required')
    data = {}
    with zipfile.ZipFile(source/'ci-logs.zip') as logs:
        for item in logs.infolist():
            if not re.fullmatch(r'\d+_check \((windows-latest|ubuntu-24\.04)\)\.txt', item.filename):
                continue
            raw = logs.read(item)
            log = re.sub(r'^\d{4}-\d\d-\d\dT\S+\s?', '', raw.decode('utf-8-sig'), flags=re.M)
            matches = list(re.finditer(r'(?m)^Ran (\d+) tests in [^\r\n]+\r?$', log))
            if len(matches) != 1:
                raise ValueError('one full test summary required')
            match = matches[0]
            status = log[match.end():].lstrip().splitlines()[0].strip()
            if match.group(1) != '439' or status != 'OK (skipped=1)':
                raise ValueError('initial skip scope differs')
            data[item.filename] = {'python_tests_collected':439, 'executed':438, 'skipped':1,
                'status':status, 'full_log_sha256':hashlib.sha256(raw).hexdigest()}
    if len(data) != 2:
        raise ValueError('two initial jobs required')
    output.mkdir()
    for path in source.iterdir():
        if not path.is_file():
            raise ValueError('unexpected capture directory')
        shutil.copyfile(path, output/path.name)
    save(output/'scope.json', {'schema':'m09-initial-ci-skip-v1', 'run_id':43804190038,
        'jobs_green':True, 'all_439_tests_executed':False, 'jobs':data,
        'collector_accepted_complete_test_claim':False,
        'collector_failure':'ValueError: hosted Python suite failed',
        'correction':'Test-only d616912/fdd323d replays rejected distribution from public frozen archive',
        'new_engine_builds':0, 'scientific_evidence_changed':False,
        'recorded_utc':datetime.now(timezone.utc).isoformat()})
    (output/'README.md').write_text('# Initial M09 hosted run — one skipped test\n\n'
        'Run 43804190038 was green on Windows and Ubuntu, but only 438 of 439 collected Python tests ran. '
        'The optional negative-distribution test depended on an ignored local acquisition directory. '
        'The strict publication collector refused a complete-test claim. All original API metadata and logs '
        'are retained here. The later test-only portability correction reads the public frozen negative '
        'archive; a new run is collected separately. No engine or scientific data changed.\n', encoding='utf-8')
    save(output/'provenance.json', {'schema':'m09-initial-ci-evidence-v1',
        'output_sha256':{p.name:sha(p) for p in sorted(output.iterdir())},
        'credentials_retained':False,'signed_log_storage_URL_retained':False})
    print(json.dumps({'output':str(output),'summaries':data},indent=2))

def configure():
    path = BASE/'config-final.json'
    if path.exists():
        raise ValueError('new final config required')
    config = json.loads((BASE/'config.json').read_text(encoding='utf-8'))
    config.update(run_id=FINAL_RUN,public_commit=PUBLIC,source_commit=SOURCE)
    save(path,config)
    print(path)

def promote():
    sys.path.insert(0,str(ROOT/'research'))
    from m09_publication import verify
    from smoke_m08_package import check_cli_test
    ci = verify(ROOT/'results/publication/r6-m09-001')
    if ci['run_id'] != FINAL_RUN or ci['public_tested_commit'] != PUBLIC:
        raise ValueError('complete final CI receipt required')
    output = ROOT/'results/engine/m09-canonical-001'
    if output.exists():
        raise ValueError('new canonical receipt required')
    plan_path = ROOT/'artifacts/generated/m09-canonical-001/plan.json'
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    target, original = ROOT/plan['target'], ROOT/plan['original_path']
    before = sha(target)
    wanted = plan['original_M09_sha256']
    if before != plan['previous_sha256'] or sha(original) != wanted:
        raise ValueError('known current/original image required')
    build = json.loads((ROOT/'artifacts/generated/m09-final-002/windows/build.json').read_text(encoding='utf-8'))
    if build['binaries']['delivered']['sha256'] != wanted:
        raise ValueError('qualified original required')
    output.mkdir()
    shutil.copyfile(Path(__file__),output/'promotion-controller.py')
    shutil.copyfile(plan_path,output/'original-plan.json')
    shutil.copyfile(original,target)
    if sha(target) != wanted:
        raise ValueError('canonical copy differs')
    checks = []
    for name, args, code in [('profile',['dev-profile'],0),('self-test',['dev-self-test'],0),
        ('refuse-vectors',['dev-vectors','1'],1),('refuse-rejections',['dev-rejection-vectors'],1),
        ('refuse-hardening',['dev-hardening'],1),('refuse-mutations',['dev-mutations'],1),
        ('refuse-timing',['dev-timing'],1)]:
        process = subprocess.run([str(target),*args],capture_output=True,timeout=120,cwd=ROOT)
        (output/(name+'.stdout')).write_bytes(process.stdout)
        (output/(name+'.stderr')).write_bytes(process.stderr)
        if process.returncode != code:
            raise ValueError('canonical smoke failed: '+name)
        if code == 1 and process.stdout:
            raise ValueError('default CLI exposed research output')
        if name == 'self-test':
            check_cli_test(json.loads(process.stdout))
        checks.append({'arguments':args,'exit_code':process.returncode,
            'stdout_sha256':hashlib.sha256(process.stdout).hexdigest(),
            'stderr_sha256':hashlib.sha256(process.stderr).hexdigest()})
    if sha(target) != wanted or sha(original) != wanted:
        raise ValueError('image changed during canonical smoke')
    save(output/'promotion.json',{'schema':'m09-canonical-promotion-v1',
        'finished_utc':datetime.now(timezone.utc).isoformat(),'target':plan['target'],
        'previous_sha256':before,'original_and_promoted_sha256':wanted,
        'source_manifest_sha256':plan['source_manifest_sha256'],
        'public_tested_commit':PUBLIC,'source_commit':SOURCE,'final_CI_run':FINAL_RUN,
        'original_plan_strengthened':'Require second CI with all439 executed and no skip, not merely first green jobs',
        'checks':checks,'new_builds':0,'fresh_round_trips':16,'implicit_rejections':16,
        'new_fuzzing_credit_seconds':0,'external_audit':False,'global_security_proved':False})
    (output/'README.md').write_text('# M09 canonical Windows CLI\n\n'
        'The original qualified Windows M09 CLI was copied to target/release/kem1536.exe after '
        'the final two-platform CI receipt passed. Its SHA-256 is checked before and after '
        'fresh profile, 16 round-trip/rejection and five research-command refusal checks. '
        'This is a copy, not a new build or timing/fuzz acquisition. The previous M08 '
        'original remains preserved in its immutable historical evidence.\n',encoding='utf-8')
    save(output/'provenance.json',{'schema':'m09-canonical-evidence-v1',
        'output_sha256':{p.name:sha(p) for p in sorted(output.iterdir())},
        'script_sha256':sha(Path(__file__))})
    print(json.dumps({'promoted':str(target),'sha256':wanted,'checks':checks},indent=2))

def readers_prepare():
    pending = ROOT/'artifacts/generated/publication/m09-reader-pending-001'
    output = ROOT/'results/publication/r6-m09-controls-001'
    if not pending.is_dir() or output.exists():
        raise ValueError('one pending reader closure required')
    shutil.move(str(pending),output)
    path = output/'source-map.json'
    mapping = json.loads(path.read_text(encoding='utf-8'))
    for name, expected in mapping['origin_git_blob_sha256'].items():
        raw = subprocess.check_output(['git','-C',str(ROOT/'publication/majax_mlkem1536'),
            'show',PUBLIC+':'+name])
        if hashlib.sha256(raw).hexdigest() != expected or sha(output/name) != expected:
            raise ValueError('frozen reader differs from tested source: '+name)
    mapping.update(public_tested_commit=PUBLIC,source_commit=SOURCE)
    save(path,mapping)
    result = subprocess.run([str(ROOT/'.tools/research-venv/Scripts/python.exe'),'-B','-m','unittest',
        'discover','-s',str(output/'research'),'-p','test_m09_publication.py','-v'],
        capture_output=True,cwd=ROOT,timeout=180)
    (output/'pure-tests.stdout').write_bytes(result.stdout)
    (output/'pure-tests.stderr').write_bytes(result.stderr)
    if result.returncode != 0 or not re.search(rb'Ran 4 tests in ',result.stderr) or not result.stderr.rstrip().endswith(b'OK'):
        raise ValueError('four frozen-reader pure tests required')
    save(output/'pure-tests.json',{'exit_code':result.returncode,'tests':4,
        'local_import_closure_files':len(mapping['origin_git_blob_sha256']),
        'all_copied_bytes_equal_tested_public_blobs':True})
    print(json.dumps({'prepared':str(output),'source_files':len(mapping['origin_git_blob_sha256']),'pure_tests':4}))

def readers_seal():
    output = ROOT/'results/publication/r6-m09-controls-001'
    if (output/'provenance.json').exists():
        raise ValueError('new reader seal required')
    result = subprocess.run([str(ROOT/'.tools/research-venv/Scripts/python.exe'),'-B',
        str(output/'research/m09_publication.py'),'verify','--output',str(ROOT/'results/publication/r6-m09-001')],
        capture_output=True,cwd=ROOT,timeout=180)
    (output/'offline-replay.stdout').write_bytes(result.stdout)
    (output/'offline-replay.stderr').write_bytes(result.stderr)
    if result.returncode != 0:
        raise ValueError('frozen reader rejected final CI receipt')
    report = json.loads(result.stdout)
    if report['run_id'] != FINAL_RUN or report['public_tested_commit'] != PUBLIC:
        raise ValueError('frozen reader replayed wrong CI receipt')
    (output/'README.md').write_text('# M09 frozen offline publication reader\n\n'
        'This 37-file static local-import closure preserves the tested publisher and its four pure tests. '
        'All copied bytes match the exact tested public Git blobs in source-map.json. '
        'The copied reader replays results/publication/r6-m09-001 offline and its four tests pass. '
        'From the repository root, run `.tools/research-venv/Scripts/python.exe -B '
        'results/publication/r6-m09-controls-001/research/m09_publication.py verify '
        '--output results/publication/r6-m09-001` (use the corresponding Python path on Linux). '
        'Network capture/status from this mini-root are not qualified. This replay runs no engine, compiler, '
        'objdump, benchmark or fuzzer and gives no external-audit credit.\n',encoding='utf-8')
    save(output/'provenance.json',{'schema':'m09-frozen-publication-controls-v1',
        'output_sha256':{p.relative_to(output).as_posix():sha(p) for p in sorted(output.rglob('*')) if p.is_file()},
        'public_tested_commit':PUBLIC,'source_commit':SOURCE,'full_tests':4,'offline_replay_passed':True,
        'network_used_for_replay':False,'new_engine_builds':0,'external_audit':False})
    print(json.dumps({'sealed':str(output),'offline_replay_passed':True,'files':len(json.loads((output/'provenance.json').read_text())['output_sha256'])}))

if __name__ == '__main__':
    {'initial':initial,'configure':configure,'promote':promote,
        'readers-prepare':readers_prepare,'readers-seal':readers_seal}[sys.argv[1]]()
