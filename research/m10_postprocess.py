"""M10 adapter for unchanged source-coverage and oracle-replay instruments.

The M08-named coverage/replay receipt schemas describe the reused instrument
format only. Their source, images, corpus and CPU are exclusively new M10
evidence. Two explicit injectable boundaries select M10 ownership and the
M10 campaign verifier; the historical instrument bytes remain unchanged.
"""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import postprocess_m08_fuzz as instrument
from m10_campaign import ROOT,owned,verify as verify_campaign


@contextmanager
def selected_instrument():
    original_owned,original_verify = instrument.owned,instrument.verify_campaign
    instrument.owned = owned
    instrument.verify_campaign = verify_campaign
    try:
        yield
    finally:
        instrument.owned,instrument.verify_campaign = original_owned,original_verify


def execute(out,target,replay_target):
    with selected_instrument():
        return instrument.postprocess(out,target,replay_target,10)


def verify(out):
    with selected_instrument():
        return instrument.verify(out)


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('run','verify'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--coverage-target',type=Path,default=ROOT/'target/m10-coverage-001')
    parser.add_argument('--replay-target',type=Path,default=ROOT/'target/m10-replay-001')
    args = parser.parse_args()
    print(json.dumps(execute(args.output,args.coverage_target,args.replay_target)
        if args.action=='run' else verify(args.output),indent=2))
