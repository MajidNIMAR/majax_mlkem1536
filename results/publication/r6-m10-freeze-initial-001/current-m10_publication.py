"""Capture/replay fresh M10 hosted checks and the original-image native smoke.

Only capture/status use authenticated API calls. Tokens stay in memory and
the shared download helper never forwards Authorization to log storage.
verify is offline and executes no engine or compiler.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile
from archive_m10 import members
from verify_m04_distribution import compiled_input_names

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / 'results/publication/r6-m08-controls-001'
sys.path.insert(0, str(SHARED))
from capture_m08_ci_receipt import authentication, read_api, download_logs
from freeze_m08_publication import check_run, check_integrity, require, sha, read, save

RUNNERS = {'windows-latest':'windows', 'ubuntu-24.04':'linux'}


def qualified_input_names(files):
    names = compiled_input_names(files)
    # These two administrative vector documents are never include! inputs.
    # Keep the broad detector for all JSON/data and newly added source files.
    names.difference_update({'vectors/README.md','vectors/nist-acvp/NIST-NOTICE.txt'})
    for name in files:
        if name.startswith(('research/m08-import-consumer/', 'research/m08-memory-probe/')):
            if '/src/' in name or name.endswith(('/Cargo.toml','/Cargo.lock','/build.rs')):
                names.add(name)
    return names


def check_smoke(value, host, config):
    require(value.get('schema') == 'm10-native-smoke-v1' and value.get('host') == host,
            'new M10 native smoke scope differs')
    wanted = config['images'][host]
    require(value.get('source_manifest_sha256') == config['source_manifest_sha256']
            and value.get('original_CLI_sha256') == wanted['CLI']
            and value.get('original_default_consumer_sha256') == wanted['consumer'], 'native M10 image differs')
    for field, count in {'fresh_round_trips':16,'implicit_rejections':16,'consumer_cases':13,'exhaustive_probes':88576,
                         'new_builds':0,'fresh_fuzzing_credit_seconds':0}.items():
        require(type(value.get(field)) is int and value[field] == count, 'native M10 counter differs: '+field)
    require(value.get('constant_time_proved') is False and value.get('external_audit') is False,
            'native M10 unsupported assurance claim')
    checks = value.get('checks', [])
    require(len(checks) == 8 and [row['exit_code'] for row in checks] == [0,1,1,1,1,1,0,0],
            'native M10 operation exits differ')
    require(checks[0]['operation'] == 'dev-self-test' and checks[-2]['operation'] == 'smoke'
            and checks[-1]['operation'] == 'exhaustive', 'native M10 operations differ')
    require([row['operation'] for row in checks[1:6]] == [['dev-vectors','1'],['dev-rejection-vectors'],
        ['dev-hardening'],['dev-mutations'],['dev-timing']], 'research command refusals differ')


def analyze(folder):
    config = read(folder/'config.json')
    run, jobs = read(folder/'run.json'), read(folder/'jobs.json')
    api_jobs = check_run(run, jobs, config['run_id'], config['public_commit'], 'main')
    manifest_raw = (folder/'tested-source-provenance.json').read_bytes()
    public_manifest = json.loads(manifest_raw)
    check_integrity(read(folder/'source-integrity.json'), public_manifest, manifest_raw, config)
    engine_raw = (folder/'engine-provenance.json').read_bytes()
    require(hashlib.sha256(engine_raw).hexdigest() == public_manifest['sha256']['results/engine/m10-001/provenance.json'],
            'tested public engine capsule provenance differs')
    qualification = json.loads(engine_raw)['groups']['qualification']
    require(qualification['archive_sha256'] == public_manifest['sha256']['results/engine/m10-001/'+qualification['archive']],
            'tested public qualification archive differs')
    source_raw = (folder/'qualified-source.json').read_bytes()
    require(hashlib.sha256(source_raw).hexdigest() == qualification['files']['source.json']['sha256']
            == config['source_manifest_sha256'], 'qualified source is not in tested public capsule')
    source = json.loads(source_raw)['source_sha256']
    compiled = {name:source[name] for name in qualified_input_names(source)}
    public_compiled = {name:public_manifest['sha256'][name] for name in qualified_input_names(public_manifest['sha256'])}
    require(compiled and compiled == public_compiled,
            'tested public compilation inputs differ from qualified engine; no implicit newline conversion allowed')
    for host in ('windows','linux'):
        raw = (folder/(host+'-build.json')).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == qualification['files'][host+'/build.json']['sha256'],
                'qualified build is not in tested public capsule')
        build = json.loads(raw)
        require(build['source_manifest_sha256'] == config['source_manifest_sha256']
                and config['images'][host] == {'CLI':build['binaries']['delivered']['sha256'],
                                             'consumer':build['binaries']['consumer']['sha256']},
                'native image configuration differs from qualified build')
    summaries = {}
    with zipfile.ZipFile(folder/'ci-logs.zip') as archive:
        infos = archive.infolist()
        require(len(infos) <= 20000 and len({item.filename for item in infos}) == len(infos)
                and sum(item.file_size for item in infos) <= 1024**3
                and all(item.file_size <= 256*1024**2 for item in infos), 'hosted log bounds differ')
        require(archive.testzip() is None, 'hosted log archive corrupt')
        for info in infos:
            match = re.fullmatch(r'\d+_check \(([^)]+)\)\.txt', info.filename)
            if not match:
                continue
            runner = match.group(1)
            require(runner in RUNNERS and runner not in summaries, 'unexpected/duplicate full hosted job')
            raw = archive.read(info)
            log = re.sub(r'^\d{4}-\d\d-\d\dT\S+\s?', '', raw.decode('utf-8-sig'), flags=re.M)
            require('##[error]' not in log, 'hosted job has workflow error')
            counts = list(re.finditer(r'(?m)^Ran (\d+) tests in [^\r\n]+\r?$', log))
            require(len(counts) == 1 and int(counts[0].group(1)) == config['python_test_count'],
                    'full hosted Python test count differs')
            require(log[counts[0].end():].lstrip().splitlines()[0].strip() == 'OK', 'hosted Python suite failed')
            smokes = [json.JSONDecoder().raw_decode(log[m.start():])[0]
                      for m in re.finditer(r'\{\s*"schema"\s*:\s*"m10-native-smoke-v1"', log)]
            require(len(smokes) == 1, 'one new original M10 native smoke required per hosted job')
            check_smoke(smokes[0], RUNNERS[runner], config)
            label = 'Windows' if RUNNERS[runner] == 'windows' else 'Ubuntu'
            steps = api_jobs[runner]['steps']
            require(len({step['name'] for step in steps}) == len(steps), 'duplicate API step')
            by_name = {step['name']:step for step in steps}
            for name in ('Check '+label, 'Run the original M10 package and import consumer on '+label):
                require(by_name.get(name,{}).get('conclusion') == 'success', 'required M10 step missing/failed')
            require(all(step['conclusion'] in ('success','skipped') for step in steps), 'unsuccessful API step')
            summaries[runner] = {'job_id':api_jobs[runner]['id'], 'python_tests':config['python_test_count'],
                'full_log':info.filename, 'full_log_sha256':hashlib.sha256(raw).hexdigest(), 'native_smoke':smokes[0]}
    require(set(summaries) == set(RUNNERS), 'both fresh hosted jobs required')
    return {'schema':'m10-hosted-integration-v1','run_id':config['run_id'],'run_url':run['html_url'],
        'public_tested_commit':config['public_commit'],'source_commit':config['source_commit'],'runners':summaries,
        'qualified_compilation_inputs_equal_tested_public_source':len(compiled),
        'historical_fuzz_time_recredited':False,'external_audit':False,'global_security_or_CT_or_erasure_proved':False}


def status(commit):
    require(re.fullmatch('[0-9a-f]{40}',commit), 'full commit required')
    runs = read_api('/actions/runs?head_sha='+commit+'&per_page=30', authentication())
    return [{key:run[key] for key in ('id','head_sha','status','conclusion','html_url')}
            for run in runs['workflow_runs'] if run['head_sha'] == commit]


def capture(config_path, integrity_path, output):
    config = read(config_path)
    headers = authentication()
    run = read_api('/actions/runs/'+str(config['run_id']),headers)
    jobs = read_api('/actions/runs/'+str(config['run_id'])+'/jobs?per_page=100',headers)
    check_run(run,jobs,config['run_id'],config['public_commit'],'main')
    require(output.resolve().parent == ROOT/'results/publication' and not output.exists(),'new publication capsule required')
    work = ROOT/'artifacts/generated/publication/m10-ci-001'/str(config['run_id'])
    work.mkdir(parents=True,exist_ok=False)
    download_logs(config['run_id'],headers,work/'ci-logs.zip')
    for name,value in (('run.json',run),('jobs.json',jobs),('config.json',config)):
        save(work/name,value)
    shutil.copyfile(integrity_path,work/'source-integrity.json')
    public = ROOT/'publication/majax_mlkem1536'
    raw = subprocess.check_output(['git','-C',str(public),'show',config['public_commit']+':PUBLICATION_PROVENANCE.json'])
    (work/'tested-source-provenance.json').write_bytes(raw)
    capsule = ROOT/'results/engine/m10-001'
    engine = read(capsule/'provenance.json')
    qualification = engine['groups']['qualification']
    require(sha(capsule/qualification['archive']) == qualification['archive_sha256'], 'local qualified archive differs')
    extracted = members(capsule/qualification['archive'])
    shutil.copyfile(capsule/'provenance.json',work/'engine-provenance.json')
    for target,member in (('qualified-source.json','source.json'),('windows-build.json','windows/build.json'),
                           ('linux-build.json','linux/build.json')):
        (work/target).write_bytes(extracted[member])
    report = analyze(work)
    output.mkdir()
    for path in work.iterdir():
        shutil.copyfile(path,output/path.name)
    save(output/'verification.json',report)
    (output/'README.md').write_text('# M10 hosted integration\n\nTwo fresh hosted full checks and native checks of the original qualified M10 CLI/API consumer, linked to committed source maps. Counts, images and scopes are explicit. No audit, CT proof or historical fuzz credit.\n',encoding='utf-8')
    save(output/'provenance.json',{'schema':'m10-publication-receipt-v1',
        'output_sha256':{p.name:sha(p) for p in output.iterdir() if p.is_file()},'credentials_retained':False,
        'signed_log_storage_URL_retained':False})
    return verify(output)


def verify(output):
    provenance = read(output/'provenance.json')
    require(provenance['schema'] == 'm10-publication-receipt-v1' and provenance['credentials_retained'] is False
            and provenance['signed_log_storage_URL_retained'] is False,'publication scope differs')
    files = {p.name:sha(p) for p in output.iterdir() if p.is_file() and p.name != 'provenance.json'}
    require(files == provenance['output_sha256'],'publication inventory differs')
    report = analyze(output)
    require(report == read(output/'verification.json'),'publication conclusion differs')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('status','capture','verify'))
    parser.add_argument('--public-commit')
    parser.add_argument('--config',type=Path)
    parser.add_argument('--integrity',type=Path)
    parser.add_argument('--output',type=Path,default=ROOT/'results/publication/r6-m10-001')
    args = parser.parse_args()
    if args.action == 'status':
        result = status(args.public_commit)
    elif args.action == 'capture':
        result = capture(args.config,args.integrity,args.output)
    else:
        result = verify(args.output)
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
