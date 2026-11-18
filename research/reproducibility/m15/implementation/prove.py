"""Universal, source-derived bounded-integer obligations for R1 arithmetic."""
import argparse
import hashlib
import json
from pathlib import Path
import time

import source_model as m
z3 = m.z3
HERE = Path(__file__).resolve().parent
z3.set_param(proof=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded(x, high):
    return z3.And(x >= 0, x <= high)


def queries(program=None):
    p = program or m.Program()
    q = m.number(p.env['Q'].term)
    x = z3.Int('input_x')
    out, checks = p.call('reduce_once', [m.Value(x, 32)])
    yield 'reduce-once', bounded(x, 2*q-1), z3.And(*checks, out.term == x % q, bounded(out.term, q-1)), \
        dict(scope='all u32 inputs below 2q', dependencies=[])
    out, checks = p.call('quotient', [m.Value(x, 32)])
    yield 'quotient', bounded(x, (1 << 32)-1), z3.And(*checks, out.term == x/q), \
        dict(scope='all u32 inputs', dependencies=[])
    out, checks = p.call('reduce_wide', [m.Value(x, 64)])
    yield 'reduce-wide', bounded(x, (1 << 64)-1), z3.And(*checks, out.term == x % q, bounded(out.term, q-1)), \
        dict(scope='all u64 inputs; research/test feature only', dependencies=[])
    a, b = z3.Ints('coefficient_a coefficient_b')
    product = a*b
    yield 'canonical-product-range', z3.And(bounded(a, q-1), bounded(b, q-1)), \
        bounded(product, (q-1)**2), dict(scope='all canonical coefficient pairs', dependencies=[])
    out, checks = p.call('product', [m.Value(a, 16), m.Value(b, 16)])
    # Prove the entire parsed reduction tail for every possible integer x in
    # a larger domain containing all a*b, then compose with the range lemma.
    abstracted = [z3.substitute(item, (product, x)) for item in [out.term, *checks]]
    require_names = set()
    def names(expr):
        if z3.is_const(expr) and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            require_names.add(str(expr))
        for child in expr.children(): names(child)
    for item in abstracted: names(item)
    m.require(require_names <= {'input_x'}, 'product abstraction did not cover every source input')
    yield 'source-product-reduction', bounded(x, (q-1)**2), \
        z3.And(*abstracted[1:], abstracted[0] == x % q, bounded(abstracted[0], q-1)), \
        dict(scope='parsed source tail, all x up to (q-1)^2; composition gives every canonical pair',
             dependencies=['canonical-product-range'], substitution='source a*b -> x, all occurrences')
    for width in range(1, 14):
        w = m.Value(z3.IntVal(width), 64)
        out, checks = p.call('compress', [m.Value(x, 16), w])
        wanted = ((x*(1 << width) + q//2) / q) % (1 << width)
        yield 'compress-'+str(width), bounded(x, q-1), \
            z3.And(*checks, out.term == wanted, bounded(out.term, (1 << width)-1)), \
            dict(scope='all canonical coefficients; fixed width '+str(width), dependencies=[])
        out, checks = p.call('decompress', [m.Value(x, 16), w])
        wanted = (x*q + (1 << (width-1))) / (1 << width)
        yield 'decompress-'+str(width), bounded(x, (1 << width)-1), \
            z3.And(*checks, out.term == wanted, bounded(out.term, q-1)), \
            dict(scope='all encoded coefficients; fixed width '+str(width), dependencies=[])


def solver_for(pre, goal):
    solver = z3.Solver()
    solver.set(timeout=20000)
    solver.add(pre, z3.Not(goal))
    return solver


def tool_bindings():
    site = m.ROOT / '.tools/m15-proof/site-packages'
    files = ('z3/z3.py', 'z3/z3core.py', 'z3/lib/libz3.dll')
    return dict(version=z3.get_version_string(), files={name: sha(site/name) for name in files})


def captured_assertions_match(script, expected):
    parsed=z3.parse_smt2_string(script)
    m.require(len(parsed)==len(expected) and all(z3.eq(a,b) for a,b in zip(parsed,expected)),
              'captured SMT assertions differ from the source-derived typed AST')


def acquire(folder='acquisition-005'):
    output = HERE / folder
    output.mkdir(exist_ok=False)
    instruments=output/'instruments';instruments.mkdir()
    for name in ('source_model.py','prove.py'):
        (instruments/name).write_bytes((HERE/name).read_bytes())
    records = []
    before = m.Program().source_bindings()
    for name, pre, goal, meta in queries():
        solver = solver_for(pre, goal)
        script = solver.to_smt2()
        (output / (name+'.smt2')).write_text(script, encoding='utf-8', newline='\n')
        started = time.monotonic()
        status = solver.check()
        row = dict(name=name, result=str(status), scope=meta,
                   seconds=time.monotonic()-started, smt2_sha256=sha(output/(name+'.smt2')))
        if status == z3.unsat:
            proof = output/(name+'.z3proof')
            proof.write_text(solver.proof().sexpr()+'\n', encoding='utf-8', newline='\n')
            row['trusted_solver_proof_sha256'] = sha(proof)
        elif status == z3.sat:
            (output/(name+'.counterexample')).write_text(str(solver.model())+'\n')
        else:
            row['reason_unknown'] = solver.reason_unknown()
        records.append(row)
        print(json.dumps(dict(obligation=name, status=str(status))), flush=True)
    after = m.Program().source_bindings()
    passed = before == after and all(r['result'] == 'unsat' for r in records)
    result = dict(schema='m15-source-arithmetic-universal-obligations-v1', status='PASS_SCOPED' if passed else 'FAIL',
                  source_before=before, source_after=after, sources_unchanged=before == after,
                  solver=tool_bindings(), obligations=records,
                  translator_sha256=sha(HERE/'source_model.py'), instrument_sha256=sha(HERE/'prove.py'),
                  parser_is_restricted_trusted_translation=True,
                  independent_proof_checker_used=False, compiled_binary_semantics_proved=False,
                  whole_KEM_formally_verified=False, constant_time_or_erasure_proved=False,
                  C01_closed=False)
    (output/'result.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    m.require(passed, 'one or more universal obligations not established; preserve acquisition')
    print(json.dumps(dict(status=result['status'], obligations=len(records))))


def verify(folder='acquisition-005'):
    output = HERE/folder
    result = json.loads((output/'result.json').read_text(encoding='utf-8'))
    m.require(result['status'] == 'PASS_SCOPED' and result['sources_unchanged'], 'incomplete acquisition')
    m.require(result['source_before'] == m.Program().source_bindings() == result['source_after'], 'source bytes changed')
    m.require(result['solver'] == tool_bindings(), 'solver or bindings differ')
    m.require(result['translator_sha256'] == sha(HERE/'source_model.py') and result['instrument_sha256'] == sha(HERE/'prove.py'),
              'translation or proof instrument changed')
    for name in ('source_model.py','prove.py'):
        m.require((output/'instruments'/name).read_bytes()==(HERE/name).read_bytes(),'captured source proof instrument differs')
    items = list(queries())
    m.require(len(items) == len(result['obligations']), 'obligation population changed')
    for (name, pre, goal, meta), row in zip(items, result['obligations']):
        m.require(name == row['name'] and row['scope'] == meta and row['result'] == 'unsat', 'scope differs')
        solver = solver_for(pre, goal)
        path = output/(name+'.smt2')
        m.require(sha(path) == row['smt2_sha256'], 'captured query hash differs')
        captured_assertions_match(path.read_text(encoding='utf-8'),solver.assertions())
        m.require(sha(output/(name+'.z3proof')) == row['trusted_solver_proof_sha256'], 'captured proof differs')
        m.require(solver.check() == z3.unsat, 'universal obligation replay did not establish UNSAT')
    print(json.dumps(dict(status='PASS_SCOPED', obligations=len(items), C01_closed=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('acquire', 'verify'))
    parser.add_argument('--directory', default='acquisition-005')
    args = parser.parse_args()
    (acquire if args.mode == 'acquire' else verify)(args.directory)
