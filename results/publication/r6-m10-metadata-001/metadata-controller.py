"""Update the authorized public repository description and verify anonymously."""
import hashlib,json,shutil,sys,urllib.request
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'research'))
from m10_publication import authentication
OUT=ROOT/'results/publication/r6-m10-metadata-001'
URL='https://api.github.com/repos/MajidNIMAR/majax_mlkem1536'
description=('MAJAX R6: working Rust module-lattice KEM research and cryptographic engineering. '
    'Rank 6 x 256, q=7681; M10 secret-owner hardening, reproducible evidence and extended qualification. Experimental R1.')
OUT.mkdir()
shutil.copyfile(__file__,OUT/'metadata-controller.py')
def save(name,value):
    with (OUT/name).open('x',encoding='utf-8',newline='\n') as f:
        json.dump(value,f,indent=2,ensure_ascii=False);f.write('\n')
headers=authentication()
headers['Content-Type']='application/json'
request={'description':description}
save('request.json',request)
with urllib.request.urlopen(urllib.request.Request(URL,data=json.dumps(request).encode(),headers=headers,method='PATCH'),timeout=60) as response:
    authenticated=json.load(response)
fields=('full_name','html_url','private','visibility','default_branch','description')
save('updated.json',{k:authenticated[k] for k in fields})
anonymous_headers={'User-Agent':'MAJAX-R6-M10-public-check','Accept':'application/vnd.github+json'}
with urllib.request.urlopen(urllib.request.Request(URL,headers=anonymous_headers),timeout=60) as response:
    anonymous=json.load(response);status=response.status
with urllib.request.urlopen(urllib.request.Request(URL+'/commits/main',headers=anonymous_headers),timeout=60) as response:
    head=json.load(response)['sha']
if not(status==200 and anonymous['private'] is False and anonymous['visibility']=='public'
       and anonymous['description']==description and head=='b96b5483655fc4447c40a1c96925bb6bb5a88c73'):
    raise ValueError('anonymous repository metadata or expected main identity differs')
save('anonymous-verification.json',{'at_utc':datetime.now(timezone.utc).isoformat(),'http_status':status,
    **{k:anonymous[k] for k in fields},'main_commit':head,'authorization_header_sent':False})
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
save('provenance.json',{'schema':'m10-public-metadata-evidence-v1',
    'files':{p.name:sha(p) for p in OUT.iterdir() if p.is_file()},'credentials_retained':False})
print(json.dumps({'public':True,'anonymous_http_status':status,'main':head,'description':description}))
