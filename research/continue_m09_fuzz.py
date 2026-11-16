"""New finite M09 sanitizer acquisition using its already built ASan images.

The previous attempt is preserved: its API worker's final short segment
finished at INITED and earned no mutation credit. New segments request 30
wall seconds even near the CPU budget, allowing corpus initialization.
This is a new acquisition, not a replacement or credit transfer.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from m09_fuzz_smoke import (ROOT, CPUS, TARGETS, inventory, read, require, save, sha, utc,
    environment, parse_init, observe_init_cpu, cpu_lower, fuzz_statistics, verify)


def worker(index, out, env):
    name, cpu = TARGETS[index], CPUS[TARGETS[index]]
    folder = out/name
    folder.mkdir()
    shutil.copytree(out/'initial-corpus'/name,folder/'corpus')
    (folder/'failures').mkdir()
    segments, credited = [], 0.0
    while credited < 30:
        require(len(segments) < 16,'bounded worker made insufficient progress')
        number = len(segments)
        log = folder/f'segment-{number:03d}.log'
        usage_path = folder/f'segment-{number:03d}-usage.json'
        command = ['/usr/bin/time','-f','{"user_seconds":%U,"system_seconds":%S,"peak_RSS_KiB":%M,"wall_seconds":%e,"exit_code":%x}',
            '-o',str(usage_path),'taskset','-c',str(cpu),str(out/'bin'/name),str(folder/'corpus'),
            f'-artifact_prefix={folder/"failures"}/',f'-seed={5090201+index*100+number}',
            '-max_total_time=30','-max_len=16384','-rss_limit_mb=2048','-timeout=60','-print_final_stats=1','-use_value_profile=1']
        started, observed, snapshot = utc(), 0, None
        with log.open('xb') as stream:
            with subprocess.Popen(command,cwd=out/'source',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as child:
                for line in child.stdout:
                    if re.search(rb'#\d+\s+INITED\b',line):
                        observed += 1
                        snapshot = observe_init_cpu(child.pid)
                    stream.write(line)
                code = child.wait()
        usage = json.loads(usage_path.read_text().splitlines()[-1])
        counters = parse_init(log.read_bytes())
        upper = None if snapshot is None else snapshot['upper_seconds']
        lower = cpu_lower(usage,upper)
        record = dict(segment=number,command=command,exit_code=code,started_utc=started,finished_utc=utc(),
            binary_sha256=sha(out/'bin'/name),log_sha256=sha(log),usage_sha256=sha(usage_path),resource_usage=usage,
            INITED_observations=observed,observed_INITED_CPU_upper_seconds=upper,observed_INITED_proc_snapshot=snapshot,
            post_INITED_CPU_lower_seconds=lower,wall_limit_requested_seconds=30,**counters,**fuzz_statistics(log))
        save(folder/f'segment-{number:03d}-result.json',record)
        require(code == usage['exit_code'] == 0 and not any((folder/'failures').iterdir()),'sanitizer worker failed; evidence retained')
        require(observed == 1 and counters['executions_after_INITED'] > 0,'no post-INIT work; evidence retained')
        require(not re.search(rb'ERROR: (?:AddressSanitizer|LeakSanitizer)',log.read_bytes()),'sanitizer reported an error')
        segments.append(record)
        credited += lower
        print(json.dumps({'target':name,'segments':len(segments),'post_INITED_CPU_lower_seconds':credited}),flush=True)
    result = dict(CPU_seconds=sum(s['resource_usage']['user_seconds']+s['resource_usage']['system_seconds'] for s in segments),
        post_INITED_CPU_lower_seconds=credited,post_INITED_CPU_budget_seconds=30,affinity_CPU=cpu,segments=segments,
        executions_after_INITED_including_repetitions=sum(s['executions_after_INITED'] for s in segments),
        final_corpus_sha256=inventory(folder/'corpus'),defects_observed=False)
    save(folder/'summary.json',result)
    return result


def run():
    require(sys.platform == 'linux','Linux coordinator required')
    previous = ROOT/'artifacts/generated/m09-fuzz-002'
    out = ROOT/'artifacts/generated/m09-fuzz-003'
    require(not out.exists() and set(CPUS.values()) <= os.sched_getaffinity(0),'new output and valid CPUs required')
    before = inventory(previous)
    require(read(previous/'summary.json')['all_four_budgets_reached'] is False
            and read(previous/'build-result.json')['exit_code'] == 0,'expected retained incomplete acquisition absent')
    out.mkdir()
    save(out/'continuation-request.json',{'previous_output':'artifacts/generated/m09-fuzz-002',
        'previous_inventory_sha256':before,'new_builds':0,'same_M09_ASan_images_reused':True,
        'previous_CPU_credited':0,'reason':'API initialization exceeded the remaining short wall request; new constant 30-second segments',
        'started_utc':utc()})
    excluded = set(TARGETS)|{'summary.json','failure.json','verification.json'}
    for path in previous.iterdir():
        if path.name in excluded:
            continue
        shutil.copytree(path,out/path.name) if path.is_dir() else shutil.copyfile(path,out/path.name)
    shutil.copyfile(Path(__file__),out/'controls/continue_m09_fuzz.py')
    config = read(out/'config.json')
    config.update(controller_sha256=inventory(out/'controls'),new_acquisition_started_utc=utc(),
        M09_images_reused_without_rebuild=True,new_builds_this_acquisition=0,previous_CPU_credited=0,
        previous_attempt_inventory_sha256=before,wall_request_policy='constant 30 seconds per segment; budget is measured CPU after INITED')
    (out/'config.json').write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
    env = environment(ROOT/'target/m09-fuzz-002')
    results, failures = {}, {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(worker,i,out,env):name for i,name in enumerate(TARGETS)}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except BaseException as error:
                failures[name] = {'type':type(error).__name__,'message':str(error)}
    save(out/'summary.json',dict(results=results,failures=failures,finished_utc=utc(),
        total_CPU_seconds=sum(row['CPU_seconds'] for row in results.values()),
        total_post_INITED_CPU_lower_seconds=sum(row['post_INITED_CPU_lower_seconds'] for row in results.values()),
        all_four_budgets_reached=set(results)==set(TARGETS) and all(row['post_INITED_CPU_lower_seconds']>=30 for row in results.values()),
        historical_CPU_credited=0,LLVM_source_coverage_measured=False,independent_oracle_replayed=False))
    save(out/'continuation-after.json',{'previous_inputs_unchanged':inventory(previous)==before,
        'previous_inventory_sha256':inventory(previous),'finished_utc':utc(),'failures':failures,'new_builds':0})
    require(not failures and inventory(previous)==before,'new acquisition incomplete; previous data preserved')
    save(out/'diagnostic-images.json',dict(binary_sha256=inventory(out/'bin'),notices_sha256=sha(out/'notices.json'),
        historical_images_reused=False,same_M09_images_reused=True))
    result = verify(out)
    save(out/'verification.json',result)
    print(json.dumps(result),flush=True)


if __name__ == '__main__':
    run()
