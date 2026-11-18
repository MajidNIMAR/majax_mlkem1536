"""Verify every installed z3 package member against the pinned official wheel."""
import hashlib
import json
from pathlib import Path
import zipfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]


def check():
    receipt=json.loads((HERE/'solver-source.json').read_text(encoding='utf-8'))
    wheel=ROOT/receipt['cache_relative'];site=ROOT/receipt['target']
    if hashlib.sha256(wheel.read_bytes()).hexdigest()!=receipt['wheel_sha256']:
        raise ValueError('pinned solver wheel differs')
    members={}
    with zipfile.ZipFile(wheel) as package:
        for item in package.infolist():
            if item.is_dir() or not item.filename.startswith('z3/'):continue
            target=(site/item.filename).resolve()
            if not target.is_relative_to(site.resolve()):raise ValueError('package member escaped target')
            raw=package.read(item)
            if target.read_bytes()!=raw:raise ValueError('installed solver member differs: '+item.filename)
            members[item.filename]=hashlib.sha256(raw).hexdigest()
    if not members:raise ValueError('empty solver package')
    return dict(schema='m15-pinned-solver-package-v1',status='PASS',
                wheel_sha256=receipt['wheel_sha256'],members_sha256=members,
                official_release_metadata_sha256=hashlib.sha256((HERE/'pypi-release.json').read_bytes()).hexdigest(),
                whole_z3_package_matches_wheel=True,
                independently_verified_solver_kernel=False)


if __name__=='__main__':
    value=check()
    path=HERE/'toolchain.json'
    if path.exists():
        if json.loads(path.read_text(encoding='utf-8'))!=value:raise ValueError('toolchain receipt differs')
    else:path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(dict(status='PASS',package_members=len(value['members_sha256']))))
