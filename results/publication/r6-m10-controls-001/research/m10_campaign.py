"""New long M10 local sanitizer campaign with conservative post-INIT CPU accounting.

All campaign outputs and targets are new; M08/M09 instruments supply parsing,
environment setup and content deduplication only, with no historical run credit.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from run_m08_fuzz import (ROOT,TARGETS,environment,inventory,read,require,save,sha,utc,
    harvest,verify_harvest,ordinary)
from m09_fuzz_smoke import observe_init_cpu,cpu_lower,parse_init,collect_notices,scalar_lock
from run_m04_fuzz_smoke import statistics as fuzz_statistics

CONTROLS = ('m10_campaign.py','m10_postprocess.py','run_m08_fuzz.py','postprocess_m08_fuzz.py',
    'replay_m08_fuzz_corpus.py','m09_fuzz_smoke.py','run_m04_fuzz_smoke.py','run_m06_fuzz.py',
    'run_m07_fuzz.py','package_m08.py','verify_m04_distribution.py')


def owned(path,parent):
    path = Path(os.path.abspath(path))
    require(path.parent==parent and path.name.startswith('m10-'),'new direct M10 child required')
    current = ROOT
    for part in path.relative_to(ROOT).parts[:-1]:
        current /= part
        ordinary(current,directory=True)
    if path.exists():
        ordinary(path,directory=True)
    return path


def check_plan(plan):
    require(plan['schema']=='m10-campaign-plan-v1' and plan['profile']=='KEM1536-DEV-Q7681-R1'
        and type(plan['post_INITED_CPU_lower_seconds_per_harness']) is int
        and plan['post_INITED_CPU_lower_seconds_per_harness']==1800
        and plan['segment_wall_seconds_requested']==300 and plan['maximum_segments_per_harness']==64
        and plan['parallel_workers']==4 and plan['historical_fuzz_CPU_seconds_credited']==0
        and plan['initialization_CPU_credited']==0,'M10 campaign budget/scope differs')
    cpus = plan['affinity_CPU_by_harness']
    require(cpus==dict(zip(TARGETS,(8,12,14,6),strict=True))
        and all(type(v) is int for v in cpus.values()),'declared four CPU bindings differ')
    require(plan['maximum_input_bytes']==16384 and plan['rss_limit_megabytes_per_worker']==2048
        and plan['individual_input_timeout_seconds']==60
        and plan['coverage_objects_separate_from_std_rebuilt_fuzz_objects'] is True
        and plan['independent_harvested_corpus_oracle_replay_required'] is True
        and plan['external_audit_in_scope'] is False,'declared corpus/coverage/oracle scope differs')
    return cpus


def worker(index,out,env,plan):
    name = TARGETS[index]
    cpu = plan['affinity_CPU_by_harness'][name]
    folder = out/name
    folder.mkdir()
    shutil.copytree(out/'initial-corpus'/name,folder/'corpus')
    (folder/'failures').mkdir()
    segments,credit = [],0.0
    while credit<plan['post_INITED_CPU_lower_seconds_per_harness']:
        number = len(segments)
        require(number<plan['maximum_segments_per_harness'],'bounded campaign made insufficient CPU progress')
        log,usage_path = folder/f'segment-{number:03d}.log',folder/f'segment-{number:03d}-usage.json'
        command = ['/usr/bin/time','-f',
            '{"user_seconds":%U,"system_seconds":%S,"peak_RSS_KiB":%M,"wall_seconds":%e,"exit_code":%x}',
            '-o',str(usage_path),'taskset','-c',str(cpu),str(out/'bin'/name),str(folder/'corpus'),
            f'-artifact_prefix={folder/"failures"}/',f'-seed={5100101+index*100+number}',
            '-max_total_time=300','-max_len=16384','-rss_limit_mb=2048','-timeout=60',
            '-print_final_stats=1','-use_value_profile=1']
        started,seen,snapshot = utc(),0,None
        with log.open('xb') as stream:
            with subprocess.Popen(command,cwd=out/'source',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as child:
                for line in child.stdout:
                    if re.search(rb'#\d+\s+INITED\b',line):
                        seen += 1
                        snapshot = observe_init_cpu(child.pid)
                    stream.write(line)
                code = child.wait()
        usage = read(usage_path)
        raw = log.read_bytes()
        counts = parse_init(raw)
        upper = None if snapshot is None else snapshot['upper_seconds']
        lower = cpu_lower(usage,upper)
        record = {'segment':number,'command':command,'exit_code':code,'started_utc':started,'finished_utc':utc(),
            'binary_sha256':sha(out/'bin'/name),'log_sha256':sha(log),'usage_sha256':sha(usage_path),
            'resource_usage':usage,'INITED_observations':seen,'observed_INITED_proc_snapshot':snapshot,
            'observed_INITED_CPU_upper_seconds':upper,'post_INITED_CPU_lower_seconds':lower,
            **counts,**fuzz_statistics(log)}
        save(folder/f'segment-{number:03d}-result.json',record)
        require(code==usage['exit_code']==0 and seen==1 and counts['executions_after_INITED']>0
            and not any((folder/'failures').iterdir())
            and not re.search(rb'ERROR: (?:AddressSanitizer|LeakSanitizer)',raw),
            'sanitizer worker failed; retain logs, inputs and interruption')
        segments.append(record)
        credit += lower
        print(json.dumps({'target':name,'segments':len(segments),'post_INITED_CPU_lower_seconds':credit,
            'budget':1800,'CPU':cpu}),flush=True)
    summary = {'affinity_CPU':cpu,'segments':segments,'CPU_seconds':sum(s['resource_usage']['user_seconds']+
        s['resource_usage']['system_seconds'] for s in segments),'post_INITED_CPU_lower_seconds':credit,
        'executions_after_INITED_including_repetitions':sum(s['executions_after_INITED'] for s in segments),
        'final_corpus_files':len(list((folder/'corpus').iterdir())),
        'final_corpus_sha256':inventory(folder/'corpus'),'defects_observed':False}
    save(folder/'summary.json',summary)
    return summary


def execute(candidate,out,target,marker_path,plan_path):
    require(sys.platform=='linux','native Linux/WSL campaign coordinator required')
    candidate = owned(candidate,ROOT/'artifacts/generated')
    out,target = owned(out,ROOT/'artifacts/generated'),owned(target,ROOT/'target')
    require(not out.exists() and not target.exists(),'new campaign and compiler target required')
    plan,marker,source = read(plan_path),read(marker_path),read(candidate/'source.json')
    cpus = check_plan(plan)
    require(set(cpus.values())<=os.sched_getaffinity(0),'declared native CPU unavailable')
    require(marker['schema']=='m10-engine-acceptance-v1' and marker['accepted_for_long_qualification'] is True
        and marker['source_manifest_sha256']==sha(candidate/'source.json')
        and marker['campaign_plan_sha256']==sha(plan_path)
        and all(marker['checks'][k] is True for k in ('latency','memory','four_image_review','finite_validation')),
        'accepted measured/reviewed source and preregistered plan required before build')
    require(inventory(candidate/'source')==source['source_sha256'],'qualified captured source changed')
    for name,expected in marker['evidence_sha256'].items():
        path = ROOT/name
        require(path.resolve().is_relative_to(ROOT) and path.is_file() and sha(path)==expected,
            'acceptance evidence changed')
    require(set(CONTROLS)==set(Path(n).name for n in CONTROLS),'unsafe controller name')
    for name in CONTROLS:
        require((ROOT/'research'/name).is_file(),'complete controllers required before launch')
    out.mkdir()
    try:
        shutil.copytree(candidate/'source',out/'source')
        shutil.copyfile(candidate/'source.json',out/'candidate-source.json')
        shutil.copyfile(marker_path,out/'accepted-marker.json')
        shutil.copyfile(plan_path,out/'campaign-plan.json')
        for name,expected in marker['evidence_sha256'].items():
            destination = out/'acceptance-evidence'/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,destination)
            require(sha(destination)==expected,'acceptance evidence changed while copying')
        for name in CONTROLS:
            dest = out/'controls'/name
            dest.parent.mkdir(exist_ok=True)
            shutil.copyfile(ROOT/'research'/name,dest)
        oracle = ROOT/'results/engine/r1-001/sources/research/kem_r1_reference.py'
        expected = read(ROOT/'results/engine/r1-001/provenance.json')['input_sha256'][oracle.relative_to(ROOT).as_posix()]
        require(sha(oracle)==expected,'frozen independent oracle changed')
        (out/'source/oracle').mkdir()
        shutil.copyfile(oracle,out/'source/oracle/kem_r1_reference.py')
        for name in TARGETS:
            seeds = ROOT/'artifacts/generated/m03-seeds-final'/name
            require(seeds.is_dir(),'synthetic compact seed corpus absent')
            dest = out/'initial-corpus'/name
            dest.mkdir(parents=True)
            for item in seeds.iterdir():
                require(item.is_file(),'flat ordinary synthetic corpus required')
                target_seed = dest/sha(item)
                if not target_seed.exists():
                    shutil.copyfile(item,target_seed)
        env = environment(target)
        cargo,rustc = (str(ROOT/'.tools/linux-cargo/bin'/n) for n in ('cargo','rustc'))
        rust = subprocess.check_output([rustc,'-Vv'],env=env,text=True)
        fuzz = subprocess.check_output([cargo,'fuzz','--version'],env=env,text=True)
        require('release: 1.91.1' in rust and fuzz.strip()=='cargo-fuzz 0.13.1','pinned instrumented tools required')
        sysroot = Path(subprocess.check_output([rustc,'--print','sysroot'],env=env,text=True).strip())
        compiler_sha = sha(sysroot/'bin/rustc')
        collect_notices(out,env,compiler_sha)
        command = ['taskset','-c',','.join(map(str,sorted(cpus.values()))),cargo,'fuzz','build',
            '--fuzz-dir',str(out/'source/fuzz'),'--target-dir',str(target),'--build-std']
        config = {'schema':'m10-long-campaign-v1','profile':source['profile'],'started_utc':utc(),
            'candidate_source_manifest_sha256':sha(candidate/'source.json'),'source_sha256':inventory(out/'source'),
            'controller_sha256':inventory(out/'controls'),'initial_corpus_sha256':inventory(out/'initial-corpus'),
            'acceptance_marker_sha256':sha(out/'accepted-marker.json'),'declared_plan_sha256':sha(out/'campaign-plan.json'),
            'post_INITED_CPU_lower_seconds_per_harness':1800,'affinity_CPU_by_harness':cpus,'parallel_workers':4,
            'build_command':command,'oracle_sha256':expected,'historical_CPU_credited':0,
            'ASAN_OPTIONS':env['ASAN_OPTIONS'],'std_rebuild_requested':True,'offline_build':True,
            'versions':{'rustc':rust,'cargo_fuzz':fuzz,'compiler_binary_sha256':compiler_sha,
                'cargo_fuzz_binary_sha256':sha(ROOT/'.tools/linux-cargo/bin/cargo-fuzz')}}
        save(out/'config.json',config)
        started = utc()
        with (out/'build.log').open('xb') as log:
            code = subprocess.run(command,cwd=out/'source',env=env,stdout=log,stderr=subprocess.STDOUT).returncode
        save(out/'build-result.json',{'exit_code':code,'started_utc':started,'finished_utc':utc(),
            'build_log_sha256':sha(out/'build.log')})
        require(code==0 and inventory(out/'source')==config['source_sha256'],'ASan/std build failed or source changed')
        std = sorted((target/'x86_64-unknown-linux-gnu/release/deps').glob('libstd-*.rlib'))
        require(std,'rebuilt standard library absent')
        (out/'bin').mkdir()
        for name in TARGETS:
            shutil.copyfile(target/'x86_64-unknown-linux-gnu/release'/name,out/'bin'/name)
            (out/'bin'/name).chmod(0o700)
        save(out/'built.json',{'binary_sha256':inventory(out/'bin'),
            'rebuilt_std_rlib_sha256':{p.name:sha(p) for p in std},
            'frozen_fuzz_lock_sha256':sha(out/'source/fuzz/Cargo.lock')})
        results,failures = {},{}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(worker,i,out,env,plan):name for i,name in enumerate(TARGETS)}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except BaseException as error:
                    failures[name] = {'type':type(error).__name__,'message':str(error)}
        results = {name:results[name] for name in TARGETS if name in results}
        summary = {'results':results,'worker_failures':failures,'finished_utc':utc(),
            'total_CPU_seconds':sum(r['CPU_seconds'] for r in results.values()),
            'total_post_INITED_CPU_lower_seconds':sum(r['post_INITED_CPU_lower_seconds'] for r in results.values()),
            'all_four_budgets_reached':set(results)==set(TARGETS) and all(r['post_INITED_CPU_lower_seconds']>=1800 for r in results.values()),
            'historical_CPU_credited':0,'standard_library_rebuilt':True,'source_line_coverage_measured':False,
            'independent_oracle_replayed':False}
        save(out/'fuzz-summary.json',summary)
        require(not failures and summary['all_four_budgets_reached'],'long campaign incomplete; evidence retained')
        harvest(out)
        save(out/'diagnostic-images.json',{'binary_sha256':read(out/'built.json')['binary_sha256'],
            'notices_sha256':sha(out/'notices.json'),'new_M10_images':True,'historical_images_reused':False})
        result = verify(out)
        save(out/'verification.json',result)
        return result
    except BaseException as error:
        if not (out/'failure.json').exists():
            save(out/'failure.json',{'type':type(error).__name__,'message':str(error),'at_utc':utc(),'evidence_retained':True})
        raise


def verify(out):
    config,built,summary,plan = (read(out/n) for n in ('config.json','built.json','fuzz-summary.json','campaign-plan.json'))
    cpus = check_plan(plan)
    require(config['schema']=='m10-long-campaign-v1' and config['historical_CPU_credited']==summary['historical_CPU_credited']==0
        and summary['all_four_budgets_reached'] is True and not summary['worker_failures'],'campaign not accepted')
    require(config['profile']==read(out/'candidate-source.json')['profile']==plan['profile']
        and config['post_INITED_CPU_lower_seconds_per_harness']==1800
        and config['affinity_CPU_by_harness']==cpus and config['parallel_workers']==4,
        'recorded campaign profile/budget/affinity differs')
    require(sha(out/'candidate-source.json')==config['candidate_source_manifest_sha256']
        and sha(out/'accepted-marker.json')==config['acceptance_marker_sha256']
        and sha(out/'campaign-plan.json')==config['declared_plan_sha256'],'source/acceptance/plan binding differs')
    marker = read(out/'accepted-marker.json')
    require(marker['schema']=='m10-engine-acceptance-v1' and marker['accepted_for_long_qualification'] is True
        and marker['source_manifest_sha256']==config['candidate_source_manifest_sha256']
        and marker['campaign_plan_sha256']==config['declared_plan_sha256']
        and all(marker['checks'][k] is True for k in ('latency','memory','four_image_review','finite_validation')),
        'campaign is not bound to an accepted engineering candidate')
    require(inventory(out/'acceptance-evidence')==marker['evidence_sha256'],
        'qualification evidence bound by acceptance marker differs')
    require(inventory(out/'source')==config['source_sha256'] and inventory(out/'controls')==config['controller_sha256']
        and inventory(out/'initial-corpus')==config['initial_corpus_sha256'],'campaign input inventories differ')
    require(all(config['source_sha256'][n]==h for n,h in read(out/'candidate-source.json')['source_sha256'].items())
        and sha(out/'source/oracle/kem_r1_reference.py')==config['oracle_sha256'],'qualified source or oracle differs')
    require(all(sha(out/'bin'/n)==built['binary_sha256'][n] for n in TARGETS)
        and built['rebuilt_std_rlib_sha256'] and read(out/'build-result.json')['exit_code']==0
        and sha(out/'build.log')==read(out/'build-result.json')['build_log_sha256'],'instrumented build evidence differs')
    require(config['std_rebuild_requested'] is True and config['offline_build'] is True
        and config['build_command'][:3]==['taskset','-c',','.join(map(str,sorted(cpus.values())))]
        and config['build_command'][-1]=='--build-std'
        and 'release: 1.91.1' in config['versions']['rustc']
        and config['versions']['cargo_fuzz'].strip()=='cargo-fuzz 0.13.1'
        and sha(out/'source/fuzz/Cargo.lock')==built['frozen_fuzz_lock_sha256'],
        'locked/std-rebuilt toolchain recipe differs')
    total,lower,executions = 0.0,0.0,0
    for index,name in enumerate(TARGETS):
        item = summary['results'][name]
        require(read(out/name/'summary.json')==item and item['affinity_CPU']==cpus[name]
            and 0<len(item['segments'])<=64,'worker identity/segment count differs')
        cpu,credit,work = 0.0,0.0,0
        for number,segment in enumerate(item['segments']):
            folder = out/name
            log,usage_path = folder/f'segment-{number:03d}.log',folder/f'segment-{number:03d}-usage.json'
            raw = log.read_bytes()
            usage = read(usage_path)
            require(segment==read(folder/f'segment-{number:03d}-result.json') and segment['segment']==number
                and sha(log)==segment['log_sha256'] and sha(usage_path)==segment['usage_sha256']
                and usage==segment['resource_usage'] and segment['exit_code']==usage['exit_code']==0
                and segment['binary_sha256']==built['binary_sha256'][name],'segment bytes/image/exit differs')
            argv = segment['command']
            require(len(argv)==18 and argv[0:2]==['/usr/bin/time','-f'] and argv[3]=='-o'
                and Path(argv[4]).name==usage_path.name and argv[5:8]==['taskset','-c',str(cpus[name])]
                and Path(argv[8]).name==name and argv[9].endswith('/'+name+'/corpus')
                and argv[10].endswith('/'+name+'/failures/') and argv[10].startswith('-artifact_prefix=')
                and argv[11:]==[f'-seed={5100101+index*100+number}','-max_total_time=300','-max_len=16384',
                    '-rss_limit_mb=2048','-timeout=60','-print_final_stats=1','-use_value_profile=1'],
                'segment command/affinity/seed differs')
            counts = parse_init(raw)
            require(segment['INITED_observations']==1 and counts['executions_after_INITED']>0
                and all(segment[k]==v for k,v in counts.items())
                and not re.search(rb'ERROR: (?:AddressSanitizer|LeakSanitizer)',raw),'post-INIT execution or sanitizer status differs')
            snapshot = segment['observed_INITED_proc_snapshot']
            upper = segment['observed_INITED_CPU_upper_seconds']
            if snapshot is None:
                require(upper is None,'unobserved initialization was credited')
            else:
                fields = snapshot['proc_stat'].rsplit(') ',1)[1].split()
                require(type(snapshot['ticks_per_second']) is int and snapshot['ticks_per_second']>0
                    and (int(fields[11])+int(fields[12])+2)/snapshot['ticks_per_second']==snapshot['upper_seconds']==upper,
                    'initial CPU upper bound differs')
            expected = cpu_lower(usage,upper)
            require(expected==segment['post_INITED_CPU_lower_seconds'],'post-INIT CPU lower bound differs')
            credit += expected
            cpu += usage['user_seconds']+usage['system_seconds']
            work += counts['executions_after_INITED']
        require(credit==item['post_INITED_CPU_lower_seconds'] and credit>=1800 and cpu==item['CPU_seconds']
            and work==item['executions_after_INITED_including_repetitions'] and not inventory(out/name/'failures')
            and inventory(out/name/'corpus')==item['final_corpus_sha256'],'worker budget/corpus differs')
        total += cpu; lower += credit; executions += work
    require(math.isclose(total,summary['total_CPU_seconds'],rel_tol=0,abs_tol=1e-9)
        and math.isclose(lower,summary['total_post_INITED_CPU_lower_seconds'],rel_tol=0,abs_tol=1e-9),'aggregate CPU differs')
    harvested = verify_harvest(out)
    notices,origin,images = (read(out/n) for n in ('notices.json','M08-license-text-origin.json','diagnostic-images.json'))
    require(inventory(out/'licenses')==notices['license_sha256']==origin['license_sha256']
        and sha(out/'M08-license-text-origin.json')==notices['source_notices_sha256']
        and notices['compiler_binary_sha256']==config['versions']['compiler_binary_sha256']==origin['compiler_binary_sha256']
        and sha(out/'metadata-fuzz.json')==notices['metadata_sha256']
        and images['binary_sha256']==built['binary_sha256'] and images['new_M10_images'] is True
        and images['historical_images_reused'] is False and images['notices_sha256']==sha(out/'notices.json'),
        'new image and license/metadata bindings differ')
    from package_m08 import diagnostic_records
    graph = diagnostic_records(read(out/'metadata-fuzz.json'),scalar_lock((out/'source/fuzz/Cargo.lock').read_text()))
    normalize = lambda values:[{k:v for k,v in row.items() if k!='metadata_id'} for row in values]
    require(graph==notices['resolved_packages'] and normalize(graph)==normalize(origin['groups']['fuzz']['resolved_packages']),
        'resolved fuzz graph differs from licensed graph')
    return {'schema':'m10-long-campaign-result-v1','profile':config['profile'],'long_campaign_completed':True,'total_CPU_seconds':total,
        'total_post_INITED_CPU_lower_seconds':lower,'executions_after_INITED_including_repetitions':executions,
        'all_four_budgets_reached':True,'harvested_unique_inputs_by_target':harvested,
        'historical_CPU_credited':0,'source_line_coverage_measured':False,'independent_oracle_replayed':False,
        'constant_time_proved':False,'external_audit':False}


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('run','verify'))
    parser.add_argument('--candidate',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--target-dir',type=Path)
    parser.add_argument('--acceptance',type=Path)
    parser.add_argument('--plan',type=Path,default=ROOT/'research/m10-campaign-plan.json')
    args = parser.parse_args()
    print(json.dumps(execute(args.candidate,args.output,args.target_dir,args.acceptance,args.plan)
        if args.action=='run' else verify(args.output),indent=2))
