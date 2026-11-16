"""Fresh native checks of the original M10 package and default API consumer."""
import argparse
import json
from pathlib import Path
from smoke_m09_package import smoke
from run_m07 import ROOT


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,default=ROOT/'results/engine/m10-001')
    args=parser.parse_args()
    report=smoke(args.snapshot)
    report['schema']='m10-native-smoke-v1'
    print(json.dumps(report,indent=2))
