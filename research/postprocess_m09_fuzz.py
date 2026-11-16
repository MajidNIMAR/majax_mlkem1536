"""Record a data-only replay after the asynchronous CPU aggregation correction."""
import hashlib
import json
from pathlib import Path
import subprocess

from m09_fuzz_smoke import ROOT, inventory, read, require, save, sha, utc, verify


def run():
    source = ROOT/'artifacts/generated/m09-fuzz-003'
    output = ROOT/'artifacts/generated/m09-fuzz-postprocess-001'
    require(not output.exists(),'new postprocessing receipt required')
    before = inventory(source)
    output.mkdir()
    save(output/'request.json',{'requested_utc':utc(),'source':'artifacts/generated/m09-fuzz-003',
        'source_inventory_sha256':before,'new_fuzzer_runs':0,'new_builds':0,
        'prior_controller_exit_code':1,'prior_error':'total CPU differs: asynchronous float addition order',
        'correction':'aggregate consistency uses absolute tolerance 1e-9 seconds only; individual CPU gates unchanged'})
    for name in ('m09_fuzz_smoke.py','postprocess_m09_fuzz.py'):
        (output/name).write_bytes((ROOT/'research'/name).read_bytes())
    report = verify(source)
    save(output/'verification.json',report)
    require(inventory(source)==before,'postprocessing changed original acquisition')
    save(output/'receipt.json',{'finished_utc':utc(),'source_inputs_unchanged':True,
        'source_inventory_sha256':inventory(source),'new_fuzzer_runs':0,'new_builds':0,
        'output_sha256':inventory(output),'status':'PASS'})
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    run()
