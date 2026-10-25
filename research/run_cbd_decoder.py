"""Execute preregistered H05 on unchanged run-010 targets and codes."""

import argparse
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import platform
import time

from block_decoder import make_code
from cbd_decoder import SCALE, decode_scalar, describe, summarize, validate_weights
from run_block_decoder import targets, target_hash

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    with path.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,indent=2,allow_nan=False)
        stream.write("\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_tables():
    from sage.all import RealBallField
    field = RealBallField(192)
    records=[]
    for q in (5,7,3329,7681):
        weights=[0]
        for d in range(1,q//2+1):
            value=-2*(field.pi()*d/q).cos().log()*SCALE
            lo,hi=int(value.lower().floor()),int(value.upper().floor())
            if lo!=hi:
                raise ArithmeticError("unresolved weight interval")
            weights.append(lo)
        validate_weights(q,weights)
        records.append(dict(q=q,scale=SCALE,weights=weights,interval_bits=192,
                            construction="RealBallField: both endpoint floors agree; zero exact"))
    return records


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    if output==ROOT or not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("new directory below NIST required")
    from verify_decoder_score_results import verify
    verify()
    from cbd_decoder_numpy import decode
    from block_decoder_numpy import warm_tables
    import numpy as np
    output.mkdir(parents=True)
    tables=build_tables()
    write(output/"weight-tables.json",tables)
    lookups={r["q"]:r["weights"] for r in tables}
    toy_rows=[]
    for q,n,k in ((5,3,1),(5,4,2),(7,4,2)):
        for family in ("repeated","radix"):
            code=make_code(q,n,k,family)
            rows=[]
            for index,target in enumerate(itertools.product(range(q),repeat=n)):
                decoded={metric:describe(code,target,decode_scalar(code,target,lookups[q],metric),lookups[q],1)
                         for metric in ("euclidean","cbd")}
                rows.append(dict(index=index,**decoded))
            toy_rows.append(dict(code=code.record(),eta=1,observations=rows,summary=summarize(rows,q,1,n)))
    write(output/"toy-comparison.json",toy_rows)
    parent=read(ROOT/"results/j2/run-010/study.json")
    old=[json.loads(s) for s in (ROOT/"results/j2/run-010/observations.jsonl").read_text().splitlines()]
    summaries,oracles,timings=[],[],[]
    with (output/"observations.jsonl").open("x",encoding="utf-8",newline="\n") as stream:
        for experiment in parent["experiments"]:
            definition=experiment["code"]
            q,n,k=definition["q"],definition["n"],definition["k"]
            eta=2 if q==3329 else 3
            code=make_code(q,n,k,definition["family"])
            weights=lookups[q]
            points=targets(q,n,256,experiment["seed_ascii"].encode("ascii"))
            warm_tables(code)
            prior=[r for r in old if r["experiment"]==experiment["experiment"]]
            rows=[]
            for index,target in enumerate(points):
                values={metric:describe(code,target,decode(code,target,weights,metric),weights,eta)
                        for metric in ("euclidean","cbd")}
                if values["euclidean"]["labels"]!=prior[index]["labels"] or values["euclidean"]["squared_norm"]!=prior[index]["squared_norm"]:
                    raise ArithmeticError("Euclidean baseline changed")
                row=dict(experiment=experiment["experiment"],index=index,target_sha256=target_hash(target),**values)
                rows.append(row)
                stream.write(json.dumps(row,allow_nan=False)+"\n")
            stream.flush()
            for j in range(8):
                block_index=j*(k-1)//7
                offset=sum(len(g) for g in code.generators[:block_index])
                generator=code.generators[block_index]
                oracles.append(dict(experiment=experiment["experiment"],index=j,block_index=block_index,q=q,
                                    values=points[j][offset:offset+len(generator)],generator=list(generator),
                                    euclidean_label=rows[j]["euclidean"]["labels"][block_index],
                                    cbd_label=rows[j]["cbd"]["labels"][block_index],
                                    certificate=rows[j]["cbd"]["certificates"][block_index]))
            durations={metric:[] for metric in ("euclidean","cbd")}
            for series in range(7):
                order=("euclidean","cbd") if series%2==0 else ("cbd","euclidean")
                for metric in order:
                    start=time.perf_counter_ns()
                    decoded=[decode(code,t,weights,metric) for t in points[series*8:series*8+8]]
                    elapsed=time.perf_counter_ns()-start
                    if any(r!=dict(labels=rows[series*8+i][metric]["labels"],certificates=rows[series*8+i][metric]["certificates"])
                           for i,r in enumerate(decoded)):
                        raise ArithmeticError("timed decoding changed")
                    durations[metric].append(elapsed)
            timing=dict(experiment=experiment["experiment"],batch_size=8,batches_ns=durations,
                        median_ns_per_decode={metric:sorted(v)[3]/8 for metric,v in durations.items()},
                        includes="validation, lookup, full symbol enumeration, selection; CBD certificate bookkeeping; warm tables")
            timings.append(timing)
            result=dict(experiment=experiment["experiment"],code=code.record(),
                        candidates_per_decode=q*k,coordinate_terms_per_decode=q*n,
                        **summarize(rows,q,eta,n))
            summaries.append(result)
            print(f"{result['experiment']}: changed={result['changed_vectors']}/256; log2 mean-bias ratio={result['log2_ratio_mean_bias']:.9f}; "
                  f"certified={result['real_optimum_certified_blocks']}/{result['blocks']}",flush=True)
    write(output/"oracle-cases.json",oracles)
    write(output/"timings.json",dict(environment=dict(platform=platform.platform(),python=platform.python_version(),numpy=np.__version__,
                                                      processor=platform.processor()),measurements=timings,
                                    limits="local paired warm-cache timings, not rop or complete attack costs"))
    write(output/"study.json",dict(experiments=summaries,scale=SCALE,protocol_commit="17f30d3",
                                  attack_costs_updated=False,profile_selected=False,j2_closed=False,
                                  model="code-only ideal independent iid-CBD secret; fixed same codes and targets as run-010",
                                  limits=["CBD integer minimizer is within eta*n/(S*ln2) log2 bias of the real optimum",
                                          "real optimum only claimed for blocks with interval/histogram certificates",
                                          "same full-alphabet candidate budget; certificate work differs",
                                          "256 synthetic paired targets per experiment, not population or tail certification",
                                          "no dual-lattice vectors, FFT score, attack success probability or security update"]))
    inputs=["research/cbd_decoder.py","research/cbd_decoder_numpy.py","research/run_cbd_decoder.py",
            "research/test_cbd_decoder.py","research/verify_cbd_decoder_results.py","research/verify_cbd_decoder_independent.py",
            "research/verify_cbd_decoder_intervals.py","docs/PROTOCOLE_H05.md",
            "research/block_decoder.py","research/block_decoder_numpy.py","research/run_block_decoder.py","research/decoder_score.py",
            "results/j2/run-010/study.json","results/j2/run-010/observations.jsonl","results/j2/run-010/provenance.json",
            "results/j2/run-011/provenance.json","results/j2/run-011/study.json",
            "research/sage-bootstrap-manifest.json","research/sage-linux-explicit.txt","research/sage-linux-packages.json"]
    # Dependency manifests that exist in this checkout are frozen individually.
    for name in inputs:
        if not (ROOT/name).is_file():
            raise FileNotFoundError(name)
    outputs=["weight-tables.json","toy-comparison.json","observations.jsonl","oracle-cases.json","timings.json","study.json"]
    write(output/"provenance.json",dict(created_utc=datetime.now(timezone.utc).isoformat(),
                                      input_sha256={n:digest(ROOT/n) for n in inputs},output_sha256={n:digest(output/n) for n in outputs}))


if __name__=="__main__":
    main()
