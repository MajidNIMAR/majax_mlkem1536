"""M10 evidence capsule; readers never launch new acquisitions."""
import argparse, gzip, hashlib, json, tarfile
from pathlib import Path
from run_m07 import ROOT, read, require, save, utc
from archive_m09 import members, inventory, data_reader, safe_name, digest, parsed
from m09_chunks import sha, recovered_bytes, PART_LIMIT
from m10_qualification_evidence import qualification_scope
from m10_measure import M09_CORE

GROUPS={'baseline':('m10-baseline-001',),'qualification':('m10-final-003',),
    'cli-review':('m10-candidate-cli-003',),'consumer-review':('m10-candidate-consumer-003',),
    'secret-review':('m10-secret-review-003',),'fuzz':('m10-fuzz-001',),
    'distribution':('m10-distribution-001',),'controls':('m10-controls-001',),
    'rejected':('m10-final-001','m10-final-002','m10-baseline-cli-001','m10-baseline-consumer-001',
        'm10-candidate-cli-001','m10-candidate-consumer-001','m10-candidate-cli-002',
        'm10-candidate-consumer-002','m10-secret-rejected-001','m10-secret-rejected-002')}
LINKS=('results/security/m10-001/provenance.json','results/security/m10-parameters-001/provenance.json',
    'results/engine/m09-001/provenance.json')


def check_link_names(links):
    require(type(links) is dict and set(links)==set(LINKS),'expected linked capsules are missing or substituted')


def bind_measurement_context(qualified,baseline):
    plan=parsed(qualified,'measurements/plan.json')
    for label,raws in (('baseline',baseline),('candidate',qualified)):
        require(digest(raws['source.json'])==plan[label+'_source_manifest_sha256']
            and qualified['measurements/context/'+label+'-source.json']==raws['source.json'],
            'archived and measured '+label+' source differ')
        for host in ('windows','linux'):
            require(qualified['measurements/context/'+label+'-'+host+'-build.json']==raws[host+'/build.json'],
                'archived and measured '+label+' build differ')


class PartWriter:
    """Small archives retain their name; no physical file exceeds90MiB."""
    def __init__(self,path):
        self.path=path
        self.buffer=bytearray()
        self.parts=[]
        self.hash=hashlib.sha256()
        self.total=0

    def write(self,raw):
        self.hash.update(raw)
        self.total+=len(raw)
        self.buffer.extend(raw)
        while len(self.buffer)>=PART_LIMIT:
            self.flush_part(bytes(self.buffer[:PART_LIMIT]))
            del self.buffer[:PART_LIMIT]
        return len(raw)

    def flush_part(self,raw):
        path=self.path.with_name(self.path.name+f'.part-{len(self.parts)+1:03d}')
        with path.open('xb') as stream:
            stream.write(raw)
        self.parts.append({'name':path.name,'bytes':len(raw),'sha256':digest(raw)})

    def finish(self):
        if self.parts:
            if self.buffer:
                self.flush_part(bytes(self.buffer))
        else:
            with self.path.open('xb') as stream:
                stream.write(self.buffer)
        self.buffer.clear()
        return {'bytes':self.total,'sha256':self.hash.hexdigest(),'parts':self.parts}


def check_parts(output):
    if not (output/'archive-parts.json').exists():
        return
    descriptor=read(output/'archive-parts.json')
    require(descriptor['engine_provenance_sha256']==sha(output/'provenance.json'),'chunk descriptor root differs')
    for name,record in descriptor['archives'].items():
        require(digest(recovered_bytes(output/name))==record['sha256'],
            'publication parts differ even if a complete archive is also present')


def group_files(roots):
    result={}
    for root in roots:
        folder=ROOT/'artifacts/generated'/root
        require(folder.is_dir() and not folder.is_symlink(),'complete generated group required: '+root)
        for path in sorted(folder.rglob('*')):
            require(not path.is_symlink(),'no linked evidence member')
            if path.is_file():
                name=(root+'/' if len(roots)>1 else '')+path.relative_to(folder).as_posix()
                safe_name(name)
                require(name not in result,'duplicate evidence member')
                result[name]=path
    require(result,'empty evidence group')
    return result


def write_group(output,name,roots):
    paths=group_files(roots)
    files={n:{'sha256':sha(p),'bytes':p.stat().st_size} for n,p in paths.items()}
    writer=PartWriter(output/(name+'.tar.gz'))
    with gzip.GzipFile(filename='',fileobj=writer,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
            for member,path in paths.items():
                info=tarfile.TarInfo(member)
                info.size=files[member]['bytes']
                info.mode=0o644
                with path.open('rb') as stream:
                    archive.addfile(info,stream)
    record=writer.finish()
    require({n:{'sha256':sha(p),'bytes':p.stat().st_size} for n,p in paths.items()}==files,
        'evidence changed during archive creation')
    return {'archive':name+'.tar.gz','archive_sha256':record['sha256'],'files':files},record


def capture_controls():
    output=ROOT/'artifacts/generated/m10-controls-001'
    require(not output.exists(),'new M10 control capture required')
    paths=list((ROOT/'research').glob('*.py'))
    paths.extend((ROOT/'results/publication/r6-m08-controls-001').glob('*.py'))
    paths.extend(ROOT/n for n in ('scripts/dev.ps1','scripts/dev.sh','.github/workflows/ci.yml',
        'research/m10-campaign-plan.json','README.md','SECURITY.md','docs/PROTOCOLE_M10.md',
        'docs/RAPPORT_RECHERCHE.md','docs/JOURNAL_RECHERCHE.md','docs/REVUE_CYCLE_SECRET_M10.md',
        'docs/SECURITE_M10.md','docs/DECISION_PARAMETRES_M10.md',
        'docs/M10_MOTEUR_ET_QUALIFICATION.md','docs/FEUILLE_DE_ROUTE_MOTEUR.md'))
    output.mkdir()
    hashes={}
    for path in paths:
        name=path.relative_to(ROOT).as_posix()
        destination=output/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        raw=path.read_bytes()
        destination.write_bytes(raw)
        hashes[name]=digest(raw)
    save(output/'control-manifest.json',{'schema':'m10-reader-controls-v1','sha256':hashes,
        'scope':'First-party readers/controllers and documents; historical data separately inventoried'})
    require(all(sha(ROOT/n)==h for n,h in hashes.items()),'live controls changed during capture')


def create(output):
    output=output.resolve()
    require(output.parent==ROOT/'results/engine' and output.name=='m10-001' and not output.exists(),
        'new M10 engine capsule required')
    capture_controls()
    output.mkdir()
    groups,parts={},{}
    for name,roots in GROUPS.items():
        print('Sealing M10 '+name,flush=True)
        groups[name],record=write_group(output,name,roots)
        if record['parts']:
            parts[name+'.tar.gz']=record
    save(output/'provenance.json',{'schema':'m10-engine-capsule-v1','profile':'KEM1536-DEV-Q7681-R1',
        'created_utc':utc(),'groups':groups,'linked_provenance_sha256':{n:sha(ROOT/n) for n in LINKS},
        'external_review_performed':False,'historical_time_recredited':False,
        'cryptographic_profile_finalized':False,'C01_closed':False})
    if parts:
        save(output/'archive-parts.json',{'schema':'m09-byte-identical-parts-v1',
            'scope':'Shared byte-preserving storage format for NEW M10 data; no M09 run credit',
            'engine_provenance_sha256':sha(output/'provenance.json'),'part_limit_bytes':PART_LIMIT,'archives':parts})
    report=verify(output)
    save(output/'verification.json',report)
    return report


def verify(output):
    provenance=read(output/'provenance.json')
    require(provenance['schema']=='m10-engine-capsule-v1' and set(provenance['groups'])==set(GROUPS)
        and provenance['profile']=='KEM1536-DEV-Q7681-R1' and provenance['external_review_performed'] is False
        and provenance['historical_time_recredited'] is False and provenance['C01_closed'] is False
        and provenance['cryptographic_profile_finalized'] is False,'M10 capsule scope differs')
    check_link_names(provenance['linked_provenance_sha256'])
    for name,checksum in provenance['linked_provenance_sha256'].items():
        safe_name(name)
        require(sha(ROOT/name)==checksum,'linked immutable capsule differs')
    check_parts(output)
    cache={}
    def recover(name):
        if name not in cache:
            record=provenance['groups'][name]
            safe_name(record['archive'])
            require('/' not in record['archive'] and sha(output/record['archive'])==record['archive_sha256'],
                'M10 logical archive differs')
            raws=members(output/record['archive'])
            require(inventory(raws)==record['files'],'M10 member inventory differs')
            cache[name]=raws
        return cache[name]
    qualified=recover('qualification')
    bind_measurement_context(qualified,recover('baseline'))
    source_sha=digest(qualified['source.json'])
    images={h:parsed(qualified,h+'/build.json')['binaries'] for h in ('windows','linux')}
    reports={}
    for name in GROUPS:
        reports[name]=verify_group(name,recover,qualified,source_sha,images)
    return {'schema':'m10-engine-verification-v1','verified':True,'groups':reports,
        'members':sum(len(recover(n)) for n in GROUPS),'source_manifest_sha256':source_sha,
        'C01_closed':False,'cryptographic_profile_finalized':False,'external_review_performed':False,
        'new_engine_or_compiler_executions_by_verifier':0,'historical_time_recredited':False}


def verify_group(name,recover,qualified,source_sha,images):
    raws=recover(name)
    if name=='qualification':
        require(parsed(raws,'measurements/plan.json')['candidate_source_manifest_sha256']==source_sha,
            'measurements concern another qualified source')
        return qualification_scope(raws)
    if name=='baseline':
        source=parsed(raws,'source.json')
        require({n.removeprefix('source/'):digest(v) for n,v in raws.items() if n.startswith('source/')}
            ==source['source_sha256'],'baseline source differs')
        require(all(source['source_sha256'][n]==h for n,h in M09_CORE.items()),'baseline core is not M09')
        for host in ('windows','linux'):
            build=parsed(raws,host+'/build.json')
            require(build['source_manifest_sha256']==digest(raws['source.json'])
                and set(build['binaries'])=={'delivered','research','consumer','latency','timing','probe'},
                'baseline source/build identity differs')
            for image in build['binaries'].values():
                require(image['exit_code']==0 and digest(raws[image['path']])==image['sha256'],'baseline image differs')
        return {'new_M10_reference_builds':12,'core':'M09','historical_campaign_credit':0}
    if name in ('cli-review','consumer-review'):
        from m10_secret_inventory import verify as review_verify
        collection=parsed(raws,'collection.json')
        kind='delivered' if name=='cli-review' else 'consumer'
        require(collection['source_manifest_sha256']==source_sha and collection['binary_kind']==kind,
            'secret inventory concerns another source or API consumer')
        for host in ('windows','linux'):
            require(collection['images'][host]['sha256']==images[host][kind]['sha256'],'reviewed image is not qualified')
        return data_reader(raws,review_verify)
    if name=='secret-review':
        from m10_secret_review import verify as secret_verify
        combined={prefix+'/'+n:v for prefix,group in (('review','secret-review'),('cli','cli-review'),
            ('consumer','consumer-review')) for n,v in recover(group).items()}
        return data_reader(combined,lambda p:secret_verify(p/'review',p/'cli',p/'consumer'))
    if name=='fuzz':
        from m10_postprocess import verify as fuzz_verify
        config=parsed(raws,'config.json')
        require(config['candidate_source_manifest_sha256']==source_sha
            and all(config['source_sha256'][n]==h for n,h in parsed(qualified,'source.json')['source_sha256'].items()),
            'long campaign concerns another source')
        gate=parsed(raws,'accepted-marker.json')
        require(gate['gate_controller_sha256']==digest(qualified['acceptance/gate-controller.py'])
            and digest(raws['accepted-marker.json'])==digest(qualified['acceptance/gate.json']),
            'root campaign gate/controller differs from qualification')
        return data_reader(raws,fuzz_verify)
    if name=='distribution':
        from m10_distribution import verify as distribution_verify
        require(parsed(raws,'result.json')['source_manifest_sha256']==source_sha,'packaged source differs')
        for host in ('windows','linux'):
            require(parsed(raws,host+'/package/provenance.json')['binary_sha256']==images[host]['delivered']['sha256'],
                'package CLI differs from qualified original')
        return data_reader(raws,distribution_verify)
    if name=='rejected':
        from m10_secret_inventory import verify as inventory_verify
        from m10_secret_review import verify_rejected,verify as intermediate_verify
        labels={'baseline-cli':'m10-baseline-cli-001','baseline-consumer':'m10-baseline-consumer-001',
            'candidate-cli':'m10-candidate-cli-001','candidate-consumer':'m10-candidate-consumer-001'}
        def negative(folder):
            for part in (r for r in GROUPS['rejected'] if '-cli-' in r or '-consumer-' in r):
                inventory_verify(folder/part)
            first=verify_rejected(folder/'m10-secret-rejected-001',{n:folder/p for n,p in labels.items()})
            second=intermediate_verify(folder/'m10-secret-rejected-002',folder/'m10-candidate-cli-002',
                folder/'m10-candidate-consumer-002',accepted=False)
            return {'first':first,'second':second,'promoted':False}
        return data_reader(raws,negative)
    record=parsed(raws,'control-manifest.json')
    require({n:digest(v) for n,v in raws.items() if n!='control-manifest.json'}==record['sha256'],
        'frozen M10 controller inventory differs')
    return {'readers_and_documents':len(record['sha256']),'new_acquisitions':0}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('create','verify'))
    parser.add_argument('--output',type=Path,default=ROOT/'results/engine/m10-001')
    args=parser.parse_args()
    print(json.dumps(create(args.output) if args.action=='create' else verify(args.output),indent=2))
