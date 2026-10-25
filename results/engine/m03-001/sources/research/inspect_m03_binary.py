"""Archive complete release disassembly and enumerate R1-reachable call sites."""
import argparse,gzip,hashlib,json,os,re,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def linux_path(path):
    path=path.resolve()
    return '/mnt/'+path.drive[0].lower()+str(path)[2:].replace('\\','/') if os.name=='nt' else str(path)
def tool(name,*args):
    prefix=['wsl','-d','Ubuntu-22.04','--'] if os.name=='nt' else []
    return subprocess.check_output([*prefix,name,*args],stderr=subprocess.PIPE)

def parse_disassembly(text):
    functions={};current=None
    for line in text.splitlines():
        label=re.fullmatch(r'([0-9a-f]+) <(.+)>:',line)
        if label:
            current=label.group(2)
            functions[current]=dict(address=label.group(1),instructions=0,conditional_branches=[],
                divisions=[],calls=[],indirect_transfers=[],conditional_moves=0)
            continue
        instruction=re.match(r'^\s*([0-9a-f]+):\s+([a-z][a-z0-9_.]*)\s*(.*)$',line)
        if current is None or not instruction:continue
        address,op,args=instruction.groups();f=functions[current];f['instructions']+=1
        item=dict(address=address,opcode=op,operands=args)
        if (op.startswith('j') and op not in ('jmp','jmpq')) or op.startswith('loop'):
            f['conditional_branches'].append(item)
        if re.fullmatch(r'i?div[bwlq]?',op):f['divisions'].append(item)
        if op.startswith('cmov'):f['conditional_moves']+=1
        if op in ('call','callq','jmp','jmpq'):
            if args.lstrip().startswith('*'):f['indirect_transfers'].append(item)
            target=re.search(r'<(.+)>',args)
            if target:
                name=re.sub(r'\+0x[0-9a-f]+$','',target.group(1))
                if op.startswith('call') or name!=current:
                    f['calls'].append(dict(**item,target=name))
    return functions

def inventory(functions):
    core={name for name in functions if any(part in name for part in
        ('kem1536::dev_kem::','kem1536::engine_poly::','kem1536::secret_box::'))}
    reachable=set(core);pending=list(core)
    while pending:
        for call in functions[pending.pop()]['calls']:
            name=call['target']
            if name in functions and name not in reachable:
                reachable.add(name);pending.append(name)
    if not core:raise ValueError('R1 core symbols absent: cannot claim inspection')
    def aggregate(names):
        return dict(functions=len(names),instructions=sum(functions[n]['instructions'] for n in names),
            conditional_branches=sum(len(functions[n]['conditional_branches']) for n in names),
            divisions=sum(len(functions[n]['divisions']) for n in names),
            indirect_transfers=sum(len(functions[n]['indirect_transfers']) for n in names))
    return dict(all_code=aggregate(functions),R1_core=aggregate(core),directly_reachable=aggregate(reachable),
        core_functions=sorted(core),reachable_functions=sorted(reachable),
        constant_time_proven=False,system_library_bodies_included=False,
        indirect_target_set_proven_complete=False,
        parser_scope='x86-64 objdump AT&T; direct call/tail transfer closure from all retained R1 symbols')

def resolve_elf_relocations(functions,text):
    addresses={int(f['address'],16):name for name,f in functions.items()}
    relocations={}
    for line in text.splitlines():
        fields=line.split()
        if len(fields)<4 or not re.fullmatch('[0-9a-f]+',fields[0]):continue
        if fields[2]=='R_X86_64_RELATIVE' and re.fullmatch('[0-9a-f]+',fields[3]):
            relocations[int(fields[0],16)]=addresses.get(int(fields[3],16))
        elif fields[2] in ('R_X86_64_GLOB_DAT','R_X86_64_JUMP_SLOT') and len(fields)>4:
            relocations[int(fields[0],16)]='EXTERNAL:'+fields[4]
    for f in functions.values():
        f['resolved_indirect_transfers']=[]
        for transfer in f['indirect_transfers']:
            slot=re.search(r'#\s+([0-9a-f]+)',transfer['operands'])
            target=relocations.get(int(slot.group(1),16)) if slot else None
            if target:
                f['resolved_indirect_transfers'].append(dict(**transfer,target=target))
                f['calls'].append(dict(**transfer,target=target))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();binary=args.binary.resolve();out=args.output.resolve()
    if not binary.is_relative_to(ROOT) or not out.is_relative_to(ROOT/'artifacts/generated') or out.exists():
        raise ValueError('local release binary and new generated output required')
    out.mkdir(parents=True)
    disassembly=tool('objdump','-d','-C','--no-show-raw-insn',linux_path(binary))
    headers=tool('objdump','-x',linux_path(binary))
    (out/'headers.txt').write_bytes(headers)
    for name,data in [('disassembly.txt.gz',disassembly),('binary.gz',binary.read_bytes())]:
        with (out/name).open('xb') as stream,gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0) as z:z.write(data)
    functions=parse_disassembly(disassembly.decode('utf-8',errors='replace'))
    if binary.read_bytes()[:4]==b'\x7fELF':
        relocations=tool('readelf','-Wr',linux_path(binary))
        (out/'relocations.txt').write_bytes(relocations)
        (out/'elf-security.txt').write_bytes(tool('readelf','-W','-l','-d',linux_path(binary)))
        resolve_elf_relocations(functions,relocations.decode())
    report=inventory(functions)
    report['resolved_indirect_transfers']=sum(len(f.get('resolved_indirect_transfers',[])) for f in functions.values())
    report.update(binary_sha256=sha(binary),binary_size=binary.stat().st_size,
        objdump_version=tool('objdump','--version').decode().splitlines()[0],
        dependency_names=re.findall(r'(?:DLL Name:|NEEDED\s+)\s*([^\s]+)',headers.decode(errors='replace')))
    (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    with gzip.open(out/'instructions.json.gz','wt',encoding='utf-8') as z:json.dump(functions,z,separators=(',',':'))
    (out/'core-functions.json').write_text(json.dumps({n:functions[n] for n in report['core_functions']},indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('core_functions','reachable_functions')},indent=2))

if __name__=='__main__':main()
