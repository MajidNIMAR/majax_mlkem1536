"""Durable Linux libFuzzer controller: CPU budgets, raw evidence, automatic archive."""
import argparse,concurrent.futures,gzip,hashlib,json,math,os,re,shutil,signal,subprocess,sys,tarfile,threading,time
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TARGETS=('import_public','import_private','decapsulate','api_sequence')
SEEDS=(5030101,5030102,5030103,5030104)
def utc():return datetime.now(timezone.utc).isoformat()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):
    tmp=p.with_name(p.name+'.tmp')
    tmp.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8',newline='\n');tmp.replace(p)
def latest(path):
    if not path.exists():return {}
    with path.open('rb') as f:
        f.seek(max(0,path.stat().st_size-65536));text=f.read().decode(errors='replace')
    matches=list(re.finditer(r'#(\d+)\s+\w+\s+cov:\s*(\d+)\s+ft:\s*(\d+)',text))
    out={}
    if matches:out=dict(executions=int(matches[-1][1]),coverage_edges=int(matches[-1][2]),features=int(matches[-1][3]))
    number=re.findall(r'stat::number_of_executed_units:\s*(\d+)',text)
    if number:out['executions']=int(number[-1])
    return out
def running_cpu(wrapper):
    try:
        children=Path(f'/proc/{wrapper}/task/{wrapper}/children').read_text().split()
        total=0
        for pid in children:
            fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
            total+=(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')
        return total
    except (OSError,ValueError,IndexError):return 0

def freeze_sources(out):
    source=out/'source';source.mkdir()
    names=['Cargo.toml','Cargo.lock','rust-toolchain.toml','docs/PROTOCOLE_M03.md',
        'research/run_m03_fuzz.py','research/prepare_m03_fuzz.py',
        'research/replay_m03_fuzz_corpus.py','scripts/m03-linux.sh']
    names += [p.relative_to(ROOT).as_posix() for folder in ('crates','profiles','fuzz') for p in (ROOT/folder).rglob('*')
        if p.is_file() and not any(part in ('target','corpus','coverage','artifacts') for part in p.relative_to(ROOT/folder).parts)]
    for name in names:
        dest=source/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
    dest=source/'oracle/kem_r1_reference.py';dest.parent.mkdir()
    shutil.copyfile(ROOT/'results/engine/r1-001/sources/research/kem_r1_reference.py',dest)
    return {p.relative_to(source).as_posix():sha(p) for p in sorted(source.rglob('*')) if p.is_file()}

def run_worker(index,out,budget,state,lock,stop):
    name=TARGETS[index];folder=out/name;folder.mkdir();corpus=folder/'corpus'
    shutil.copytree(out/'initial-corpus'/name,corpus)
    artifacts=folder/'failures';artifacts.mkdir()
    total_cpu=0.;segments=[];number=0
    try:
        while total_cpu<budget and not stop.is_set():
            remaining=budget-total_cpu;seconds=max(10,min(600,math.ceil(remaining)))
            log=folder/f'segment-{number:03d}.log';usage=folder/f'segment-{number:03d}-usage.json'
            command=['/usr/bin/time','-f','{"user_seconds":%U,"system_seconds":%S,"peak_RSS_KiB":%M,"wall_seconds":%e,"exit_code":%x}',
                '-o',str(usage),'taskset','-c',str(2+index*2),str(out/'bin'/name),str(corpus),
                f'-artifact_prefix={artifacts}/',f'-seed={SEEDS[index]+number}',f'-max_total_time={seconds}',
                '-max_len=16384','-rss_limit_mb=2048','-timeout=60','-print_final_stats=1','-use_value_profile=1']
            env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1')
            started=time.monotonic();started_utc=utc()
            with log.open('xb') as output:
                with subprocess.Popen(command,stdout=output,stderr=subprocess.STDOUT,env=env,start_new_session=True) as process:
                    while process.poll() is None:
                        with lock:state[name]=dict(status='running',segment=number,pid=process.pid,
                            completed_CPU_seconds=total_cpu,current_CPU_seconds=running_cpu(process.pid),
                            elapsed_segment_seconds=time.monotonic()-started,
                            corpus_files=sum(1 for _ in corpus.iterdir()),**latest(log))
                        if stop.wait(5):
                            os.killpg(process.pid,signal.SIGTERM);process.wait();break
                    exit_code=process.wait()
            try:measured=json.loads(usage.read_text().splitlines()[-1])
            except (ValueError,OSError,IndexError):measured={}
            cpu=measured.get('user_seconds',0)+measured.get('system_seconds',0)
            total_cpu+=cpu
            segments.append(dict(segment=number,started_utc=started_utc,finished_utc=utc(),
                wall_seconds_observed=time.monotonic()-started,command=command,exit_code=exit_code,
                resource_usage=measured,**latest(log)))
            write(folder/'segments.json',segments)
            if exit_code!=0 or any(artifacts.iterdir()) or not measured:
                stop.set();raise RuntimeError(f'{name}: segment {number} failed, evidence preserved')
            number+=1
        result=dict(status='complete' if total_cpu>=budget else 'interrupted',CPU_seconds=total_cpu,
            segments=len(segments),executions=sum(s.get('executions',0) for s in segments),
            corpus_files=sum(1 for _ in corpus.iterdir()),budget_CPU_seconds=budget)
    except BaseException as error:
        stop.set();result=dict(status='failed',CPU_seconds=total_cpu,error=str(error),segments=len(segments))
    with lock:state[name]=result
    write(folder/'result.json',result)
    return result

def postprocess(out):
    env=dict(os.environ,CARGO_HOME=str(ROOT/'.tools/linux-cargo'),RUSTUP_HOME=str(ROOT/'.tools/linux-rustup'),
        RUSTC_BOOTSTRAP='1',RUSTUP_TOOLCHAIN='1.91.1-x86_64-unknown-linux-gnu')
    env['PATH']=str(ROOT/'.tools/linux-cargo/bin')+':/usr/local/bin:/usr/bin:/bin'
    cargo=ROOT/'.tools/linux-cargo/bin/cargo'
    sysroot=Path(subprocess.check_output([str(ROOT/'.tools/linux-cargo/bin/rustc'),'--print','sysroot'],env=env,text=True).strip())
    llvm=sysroot/'lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov'
    cov={}
    for name in TARGETS:
        command=[str(cargo),'fuzz','coverage',name,str(out/name/'corpus'),'--fuzz-dir',str(out/'source/fuzz'),
            '--target-dir',str(out/'coverage-build'),'--','-timeout=60','-rss_limit_mb=2048']
        with (out/f'{name}-coverage.log').open('wb') as log:
            subprocess.run(command,cwd=out/'source',env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        profile=out/'source/fuzz/coverage'/name/'coverage.profdata'
        binary=out/'coverage-build/x86_64-unknown-linux-gnu/release'/name
        raw=subprocess.check_output([str(llvm),'export','-summary-only',str(binary),'-instr-profile='+str(profile)],env=env)
        exported=json.loads(raw);write(out/f'{name}-coverage.json',exported)
        cov[name]=[f for item in exported['data'] for f in item['files'] if '/crates/kem1536/src/' in f['filename']]
    write(out/'coverage-summary.json',cov)
    def winpath(path):return subprocess.check_output(['wslpath','-w',str(path)],text=True).strip()
    with (out/'oracle-replay.log').open('wb') as log:
        subprocess.run([str(ROOT/'.tools/research-venv/Scripts/python.exe'),
            winpath(out/'source/research/replay_m03_fuzz_corpus.py'),'--campaign',winpath(out)],
            stdout=log,stderr=subprocess.STDOUT,check=True)
    return dict(coverage_exported=True,independent_corpus_replayed=True)

def finalize(out,source_hashes,results,archive):
    checks={}
    if archive and all(r['status']=='complete' for r in results.values()):
        try:checks=postprocess(out)
        except BaseException as error:checks=dict(error=str(error),coverage_and_oracle_validation_complete=False)
    summary=dict(finished_utc=utc(),workers=results,total_CPU_seconds=sum(r.get('CPU_seconds',0) for r in results.values()),
        all_budgets_reached=all(r['status']=='complete' for r in results.values()),
        defects_resolved=False if any(r['status']=='failed' for r in results.values()) else None,
        T07_duration_reached=sum(r.get('CPU_seconds',0) for r in results.values())>=86400,
        T07_validated=False,reason='Human/agent review of final coverage and corpus evidence required before validation',
        automatic_postprocessing=checks,
        source_sha256=source_hashes)
    write(out/'summary.json',summary)
    report=['# Campagne M03 — bilan automatique','',f"Fin UTC : {summary['finished_utc']}",
        f"Temps CPU cumulé mesuré : {summary['total_CPU_seconds']:.2f} s.",
        f"Budgets atteints : {summary['all_budgets_reached']}. T07 validé : non.",
        '', 'Le corpus final et la couverture doivent être revus ; aucun audit ou temps constant démontré.','']
    for name,result in results.items():report.append(f"- {name} : {json.dumps(result,ensure_ascii=False)}")
    (out/'RAPPORT_AUTOMATIQUE.md').write_text('\n'.join(report)+'\n',encoding='utf-8',newline='\n')
    if archive:
        if archive.exists():raise ValueError('archive already exists: refusing overwrite')
        archive.mkdir(parents=True)
        for name in ('config.json','summary.json','RAPPORT_AUTOMATIQUE.md'):
            shutil.copyfile(out/name,archive/name)
        with tarfile.open(archive/'campaign.tar.gz','w:gz') as tar:
            for name in ['source','bin','initial-corpus',*TARGETS]:tar.add(out/name,arcname=name)
            for path in sorted(out.iterdir()):
                if path.is_file() and path.name not in ('config.json','summary.json','RAPPORT_AUTOMATIQUE.md'):
                    tar.add(path,arcname=path.name)
        write(archive/'provenance.json',dict(input_sha256={},output_sha256={p.name:sha(p) for p in archive.iterdir() if p.is_file()}))
        message=(f"\n\n## Actualisation automatique M03 — {summary['finished_utc']}\n\n"
            f"Temps CPU de fuzzing cumulé mesuré : {summary['total_CPU_seconds']:.2f} s. "
            f"Budgets atteints : {summary['all_budgets_reached']}. "
            f"Post-traitements : {json.dumps(checks,ensure_ascii=False)}. "
            f"Preuves dans results/engine/{archive.name}. "
            "La revue finale reste requise ; T07 et la validation globale ne sont pas déclarés acquis automatiquement.\n")
        for name in ('RAPPORT_RECHERCHE.md','JOURNAL_RECHERCHE.md'):
            with (ROOT/'docs'/name).open('a',encoding='utf-8',newline='\n') as stream:stream.write(message)
    return summary

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--cpu-seconds',type=int,default=21600)
    parser.add_argument('--archive',type=Path)
    args=parser.parse_args();out=args.output.resolve()
    if os.name=='nt' or not out.is_relative_to(ROOT/'artifacts/generated') or out.exists() or not 10<=args.cpu_seconds<=21600:
        raise ValueError('new local Linux campaign output and 10..21600 CPU seconds per target required')
    archive=args.archive.resolve() if args.archive else None
    if archive and (archive.parent!=ROOT/'results/engine' or archive.exists()):raise ValueError('new engine snapshot required')
    out.mkdir(parents=True);(out/'bin').mkdir()
    source_hashes=freeze_sources(out)
    shutil.copytree(ROOT/'artifacts/generated/m03-seeds-final',out/'initial-corpus')
    binaries={}
    for name in TARGETS:
        dest=out/'bin'/name;shutil.copyfile(ROOT/'target/m03-fuzz/x86_64-unknown-linux-gnu/release'/name,dest)
        dest.chmod(0o700);binaries[name]=sha(dest)
    replay=ROOT/'target/m03-windows/release/m03-replay.exe'
    if archive:
        dest=out/'bin/m03-replay.exe';shutil.copyfile(replay,dest);binaries['m03-replay.exe']=sha(dest)
    config=dict(started_utc=utc(),controller_pid=os.getpid(),CPU_seconds_per_worker=args.cpu_seconds,
        targets=TARGETS,seeds=SEEDS,binary_sha256=binaries,source_sha256=source_hashes,
        compiler='Rust 1.91.1',cargo_fuzz='0.13.1',libfuzzer_sys='0.4.13',standard_library_rebuilt=True,
        segment_limit_wall_seconds=600,rss_limit_mb=2048,max_input_bytes=16384,
        output=str(out),archive=str(archive) if archive else None)
    write(out/'config.json',config)
    lock=threading.Lock();stop=threading.Event();state={name:dict(status='starting') for name in TARGETS}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures={name:pool.submit(run_worker,i,out,args.cpu_seconds,state,lock,stop) for i,name in enumerate(TARGETS)}
        while not all(f.done() for f in futures.values()):
            if (out/'STOP').exists():stop.set()
            with lock:write(out/'progress.json',dict(updated_utc=utc(),controller_pid=os.getpid(),workers=state))
            time.sleep(10)
        results={name:f.result() for name,f in futures.items()}
    with lock:write(out/'progress.json',dict(updated_utc=utc(),controller_pid=os.getpid(),workers=state))
    print(json.dumps(finalize(out,source_hashes,results,archive),indent=2))
    if any(r['status']!='complete' for r in results.values()):sys.exit(1)

if __name__=='__main__':main()
