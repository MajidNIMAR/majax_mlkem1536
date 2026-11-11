import hashlib,json,os,re,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def inventory():
 names=subprocess.check_output(['git','ls-files','-c','-o','--exclude-standard','-z'],cwd=ROOT).decode('utf-8').split('\0')
 return {n:sha(ROOT/n) for n in sorted(set(names)) if n and (ROOT/n).is_file()}
command=['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/dev.ps1','check']
before=inventory(); started=datetime.now(timezone.utc).isoformat()
print('Running complete Windows dev.ps1 check; output retained in windows-check.log',flush=True)
with (OUT/'windows-check.log').open('xb') as log:
 completed=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
after=inventory(); text=(OUT/'windows-check.log').read_text(encoding='utf-8',errors='replace')
receipt={'command':command,'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'exit_code':completed.returncode,'working_tree_files_sha256':before,'source_files_unchanged_during_check':before==after,'log_sha256':sha(OUT/'windows-check.log'),'capture_sha256':sha(Path(__file__)),'python_tests':re.findall(r'Ran (\d+) tests in [^\r\n]+',text),'scope':'Complete local Windows check of working-tree bytes; historical data replays and finite fresh self-tests, no renewed measurement or fuzz campaign.'}
with (OUT/'windows-check.json').open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2);f.write('\n')
print(json.dumps({k:v for k,v in receipt.items() if k!='working_tree_files_sha256'}),flush=True)
sys.exit(completed.returncode if completed.returncode else (0 if before==after else 3))
