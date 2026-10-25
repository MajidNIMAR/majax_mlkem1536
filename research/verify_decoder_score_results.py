"""Standard-Python integrity, residual, moment and covariance replay of run-011."""

import hashlib
import json
import math
from pathlib import Path

from decoder_score import LN2, centered, distribution_summary, integer_moments, log_phi, score_bank
from run_block_decoder import targets

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-011"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def compare(a, b):
    if isinstance(a, float) or isinstance(b, float):
        if not math.isclose(a,b,rel_tol=1e-10,abs_tol=1e-8):
            raise ValueError("score floating replay mismatch")
    elif isinstance(a,dict) and isinstance(b,dict):
        if set(a)!=set(b):
            raise ValueError("score dictionary fields mismatch")
        for key in a:
            compare(a[key],b[key])
    elif isinstance(a,list) and isinstance(b,list):
        if len(a)!=len(b):
            raise ValueError("score list length mismatch")
        for x,y in zip(a,b):
            compare(x,y)
    elif a!=b:
        raise ValueError("score exact replay mismatch")


def verify():
    for manifest in ("provenance.json","independent-provenance.json","numeric-provenance.json"):
        provenance=read(RUN/manifest)
        for group,base in (("input_sha256",ROOT),("output_sha256",RUN)):
            for name,expected in provenance[group].items():
                path=(base/name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                    raise ValueError(f"decoder score checksum mismatch: {name}")
    study=read(RUN/"study.json")
    if len(study["results"])!=8 or study["profile_selected"] or study["j2_closed"] or study["attack_costs_updated"]:
        raise ValueError("decoder score scope mismatch")
    parent=read(ROOT/"results/j2/run-010/study.json")
    source=[json.loads(s) for s in (ROOT/"results/j2/run-010/observations.jsonl").read_text(encoding="utf-8").splitlines()]
    rows=[json.loads(s) for s in (RUN/"residuals.jsonl").read_text(encoding="utf-8").splitlines()]
    if len(rows)!=2048:
        raise ValueError("2048 residuals required")
    moments,banks=read(RUN/"coordinate-moments.json"),read(RUN/"score-banks.json")
    for experiment,summary,moment,bank in zip(parent["experiments"],study["results"],moments,banks):
        name=experiment["experiment"]
        code=experiment["code"]
        q,eta=code["q"],2 if code["q"]==3329 else 3
        actual=[r for r in rows if r["experiment"]==name]
        observations=[r for r in source if r["experiment"]==name]
        points=targets(q,code["n"],256,experiment["seed_ascii"].encode("ascii"))
        residuals=[]
        if [r["index"] for r in actual]!=list(range(256)):
            raise ValueError("residual index mismatch")
        for row,old,target in zip(actual,observations,points):
            word=[a*g%q for a,block in zip(old["labels"],code["generators"]) for g in block]
            r=[centered(x-y,q) for x,y in zip(target,word)]
            if r!=row["residual"] or sum(x*x for x in r)!=row["squared_norm"] or row["squared_norm"]!=old["squared_norm"]:
                raise ValueError("parent residual reconstruction mismatch")
            compare(log_phi(r,q,eta)/LN2,row["log2_CBD"])
            compare(-eta*math.pi**2*row["squared_norm"]/q**2/LN2,row["log2_Gaussian_upper"])
            residuals.append(r)
        compare(summary,dict(experiment=name,q=q,eta=eta,block_sizes=code["block_sizes"],**distribution_summary(residuals,q,eta,code["block_sizes"])))
        compare(moment,dict(experiment=name,**integer_moments(residuals)))
        compare(bank,dict(experiment=name,**score_bank(residuals,q,eta)))
    controls=read(RUN/"equal-norm-controls.json")
    if len(controls)!=18:
        raise ValueError("18 equal-norm controls required")
    groups={}
    for row in controls:
        if sum(x*x for x in row["residual"])!=row["amplitude"]**2:
            raise ValueError("equal-norm control energy mismatch")
        compare(log_phi(row["residual"],row["q"],row["eta"])/LN2,row["log2_CBD"])
        groups.setdefault((row["q"],row["amplitude"]),[]).append(row)
    for group in groups.values():
        if len(group)!=3 or len({r["squared_norm"] for r in group})!=1 or max(r["log2_CBD"] for r in group)-min(r["log2_CBD"] for r in group)<=1e-8:
            raise ValueError("directional control missing")
    toys=read(RUN/"toy-laws.json")
    if len(toys)!=6 or sum(t["uniform_targets"] for t in toys)!=6302:
        raise ValueError("six complete toy laws required")
    for t in toys:
        if sum(t["phase_weights"])!=t["phase_denominator"] or not t["block_law_matches_joint"]:
            raise ValueError("toy phase mass/block identity mismatch")
        if any(a*t["phase_denominator"]!=b*t["block_product_denominator"] for a,b in zip(t["block_product_phase_weights"],t["phase_weights"])):
            raise ValueError("toy exact block factorization failed")
    independent=read(RUN/"independent-verification.json")
    if independent["complete_targets"]!=6302 or not independent["joint_phase_laws_matched"] or not independent["shared_secret_moments_matched"]:
        raise ValueError("independent bit check missing")
    numeric=read(RUN/"numeric-verification.json")
    if not numeric["all_passed"] or len(numeric["checks"])!=114 or numeric["maximum_absolute_log2_delta"]>=1e-8:
        raise ValueError("high-precision checks missing")
    return dict(snapshot="run-011",residuals_reconstructed=2048,exact_integer_moment_matrices=8,
                score_banks=8,terms_per_bank=32,equal_norm_controls=18,exact_toy_targets=6302,
                high_precision_checks=114,attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=="__main__":
    print(json.dumps(verify(),indent=2))
