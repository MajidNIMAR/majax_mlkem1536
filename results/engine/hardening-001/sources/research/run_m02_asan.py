"""Run the instrumented Linux CLI against the complete frozen M02 mutations."""

import argparse
from datetime import datetime,timezone
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import subprocess

from validate_hardening_m02 import ROOT,RUN,command,sha


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();binary=args.binary.resolve();output=args.output.resolve()
    if not binary.is_relative_to(ROOT) or not output.is_relative_to(ROOT) or output.exists() or output==ROOT:
        raise ValueError('local ASan binary and new output directory required')
    output.mkdir(parents=True)
    def cmd(op):
        raw=command(binary,[op])
        return raw[:4]+['env','ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1']+raw[4:]
    with (output/'stderr.log').open('wb') as errors:
        formats=subprocess.run(cmd('dev-hardening'),stdout=subprocess.PIPE,stderr=errors,check=True)
        actual=json.loads(formats.stdout)
        expected=json.loads((RUN/'platforms.json').read_text())['windows']['formats']
        if actual!=expected:
            raise ValueError('instrumented format campaign differs')
        count=0;digest=hashlib.sha256()
        with gzip.open(RUN/'mutations.jsonl.gz','rb') as saved:
            with subprocess.Popen(cmd('dev-mutations'),stdout=subprocess.PIPE,stderr=errors) as process:
                try:
                    for ours,reference in itertools.zip_longest(process.stdout,saved):
                        if ours is None or reference is None or json.loads(ours)!=json.loads(reference):
                            raise ValueError(f'instrumented mutation mismatch at {count}')
                        digest.update(ours);count+=1
                except BaseException:
                    process.terminate();process.wait();raise
                if process.wait()!=0 or count!=10000:
                    raise ValueError('instrumented mutation run failed')
    result=dict(created_utc=datetime.now(timezone.utc).isoformat(),instrumentation='Rust AddressSanitizer + leak detection',
        target='x86_64-unknown-linux-gnu under WSL2',rust_bootstrap_for_sanitizer=True,
        prebuilt_standard_library_instrumented=False,format_inputs=20000,mutation_cases=count,
        all_outputs_match_independently_verified_corpus=True,process_exit_codes=[0,0],
        binary_sha256=sha(binary),stderr_sha256=sha(output/'stderr.log'),
        raw_output_sha256=digest.hexdigest(),input_sha256={str(p.relative_to(ROOT)).replace('\\','/'):sha(p)
            for p in (RUN/'platforms.json',RUN/'mutations.jsonl.gz',Path(__file__).resolve())})
    (output/'report.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
