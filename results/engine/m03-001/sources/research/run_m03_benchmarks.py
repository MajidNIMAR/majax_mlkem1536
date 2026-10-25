"""Run P01 sequentially, capture all observations and query OS peak memory."""
import argparse,ctypes,gzip,hashlib,json,os,platform,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
from summarize_m03_bench import summarize

ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def utc():return datetime.now(timezone.utc).isoformat()
def posix(p):return '/mnt/'+p.drive[0].lower()+str(p)[2:].replace('\\','/')
def capture(*args):return subprocess.check_output(args,stderr=subprocess.STDOUT).decode(errors='replace')
def write(p,obj):p.write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8',newline='\n')

def windows_peak(binary,engine):
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)]+[(n,ctypes.c_size_t) for n in
            ('PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
             'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage','PrivateUsage')]
    info=Counters();info.cb=ctypes.sizeof(info)
    with subprocess.Popen([str(binary),'rss',engine],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as p:
        try:
            line=p.stdout.readline();result=json.loads(line)
            psapi=ctypes.WinDLL('psapi',use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype=wintypes.BOOL
            if not psapi.GetProcessMemoryInfo(int(p._handle),ctypes.byref(info),info.cb):raise ctypes.WinError(ctypes.get_last_error())
            _,errors=p.communicate(b'\n',timeout=60)
            if p.returncode or errors or result!={'round_trips':1000,'secrets_printed':False}:raise ValueError('RSS measurement failed')
            return dict(engine=engine,peak_working_set_bytes=info.PeakWorkingSetSize,
                peak_pagefile_usage_bytes=info.PeakPagefileUsage,scope='OS process peak after 1000 full round trips, before exit')
        except BaseException:p.kill();p.wait();raise

def measure(binary,out,label):
    command=[str(binary),'measure'] if label=='windows' else ['wsl','-d','Ubuntu-22.04','--','taskset','-c','0',posix(binary),'measure']
    start=utc()
    with (out/f'{label}-stderr.log').open('wb') as errors:
        with subprocess.Popen(command,stdout=subprocess.PIPE,stderr=errors) as p:
            try:
                if label=='windows':
                    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
                    kernel.SetProcessAffinityMask.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
                    if not kernel.SetProcessAffinityMask(int(p._handle),1):raise ctypes.WinError(ctypes.get_last_error())
                raw=p.stdout.read()
                if p.wait()!=0:raise ValueError('benchmark process failed')
            except BaseException:p.kill();p.wait();raise
    rows=[json.loads(line) for line in raw.splitlines()]
    result=summarize(rows)
    with (out/f'{label}-observations.jsonl.gz').open('xb') as stream,gzip.GzipFile(filename='',fileobj=stream,mode='wb',mtime=0) as z:z.write(raw)
    result.update(started_utc=start,finished_utc=utc(),binary_sha256=sha(binary),affinity_mask=1,
        exit_code=0,affinity_note='Windows logical CPU 0 or WSL virtual CPU 0; physical mapping between OSes not proven')
    write(out/f'{label}-summary.json',result)
    print(label+': 30000 observations validated',flush=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve()
    if os.name!='nt' or not out.is_relative_to(ROOT/'artifacts/generated') or out.exists():raise ValueError('new local output required on Windows host')
    out.mkdir(parents=True)
    binaries={'windows':ROOT/'target/m03-windows/release/kem1536-bench.exe','linux':ROOT/'target/m03-linux/release/kem1536-bench'}
    metadata=dict(platform=platform.platform(),cpu=capture('powershell','-NoProfile','-Command',
        'Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | ConvertTo-Json'),
        power_scheme=capture('powercfg','/getactivescheme'),
        linux_cpu=capture('wsl','-d','Ubuntu-22.04','--','lscpu'),
        linux_kernel=capture('wsl','-d','Ubuntu-22.04','--','uname','-a'),
        frequency_policy='Windows active power scheme recorded; no fixed CPU frequency; WSL governor not controlled',
        compiler_pin=(ROOT/'rust-toolchain.toml').read_text(),
        source_sha256={p:sha(ROOT/p) for p in ('crates/kem1536-bench/src/main.rs','Cargo.lock','research/run_m03_benchmarks.py','research/summarize_m03_bench.py')},
        heavy_campaigns_started_by_this_task_during_measurement=False)
    write(out/'environment.json',metadata)
    for label,binary in binaries.items():measure(binary,out,label)
    memory=[windows_peak(binaries['windows'],e) for e in ('R1','ML-KEM-1024')]
    for engine in ('R1','ML-KEM-1024'):
        usage=out/f'linux-{engine}-rss.txt'
        p=subprocess.run(['wsl','-d','Ubuntu-22.04','--','/usr/bin/time','-f','%M','-o',posix(usage),
            'taskset','-c','0',posix(binaries['linux']),'rss',engine],input=b'',capture_output=True,check=True)
        if json.loads(p.stdout)!={'round_trips':1000,'secrets_printed':False}:raise ValueError('Linux RSS exchange failure')
        memory.append(dict(engine=engine,platform='linux',peak_RSS_KiB=int(usage.read_text().strip()),
            scope='GNU time process peak, 1000 full round trips'))
    write(out/'memory.json',dict(observations=memory,algorithm_only_memory_measured=False,
        caveat='RSS/working set includes executable, runtime, allocator and harness; definitions differ across OSes'))
    print('OS process peak memory captured',flush=True)

if __name__=='__main__':main()
