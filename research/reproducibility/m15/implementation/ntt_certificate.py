"""Algebraic certificate for the checked R1 public transform schedule.

Universal extension uses linearity and evaluation at roots of X^N+1;
it does not enumerate all polynomial inputs. The trusted source/template
mapping is explicit and separate from the SMT straight-line translation.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
import source_model as m

HERE = Path(__file__).resolve().parent

TEMPLATE = '''
#[cfg(test)]
TRANSFORM_CALLS.with(|calls| calls.set(calls.get() + 1));
for i in 0..N {
 let j = (i as u8).reverse_bits() as usize;
 if i < j { values.swap(i, j); }
}
for stage in 0..8 {
 let length = 2 << stage;
 let half = length >> 1;
 let stage_twiddles = &twiddles[half - 1..length - 1];
 let mut start = 0;
 while start < N {
  for (offset, &twiddle) in stage_twiddles.iter().enumerate() {
   let low = values[start + offset];
   let high = product(values[start + offset + half], std::hint::black_box(twiddle));
   values[start + offset] = reduce_once(u32::from(low) + u32::from(high));
   values[start + offset + half] = reduce_once(u32::from(low) + u32::from(Q) - u32::from(high));
  }
  start += length;
 }
}
'''

PUBLIC_TEMPLATES = {
'public_power': '''let mut result = 1_u32; while exponent != 0 {
 if exponent & 1 != 0 { result = result * base as u32 % Q as u32; }
 base = (base as u32 * base as u32 % Q as u32) as u16;
 exponent >>= 1; } result as u16''',
'public_powers': '''let mut values = [0; N]; let mut i = 0; let mut value = scale;
 while i < N { values[i] = value; value = (value as u32 * root as u32 % Q as u32) as u16;
 i += 1; } values''',
'stage_twiddles': '''let mut twiddles = [0; N - 1]; let mut stage = 0;
 while stage < 8 { let half = 1 << stage;
 let stage_root = public_power(root, N >> (stage + 1)); let mut value = 1;
 let mut offset = 0; while offset < half { twiddles[half - 1 + offset] = value;
 value = (value as u32 * stage_root as u32 % Q as u32) as u16; offset += 1; }
 stage += 1; } twiddles''',
'forward_into': '''for (i, &twist) in TWIST.iter().enumerate() {
 out.values[i] = product(self.coefficients[i], twist); }
 transform(&mut out.values, &FORWARD_TWIDDLES);''',
'inverse_into': '''out.coefficients.copy_from_slice(&self.values[..]);
 transform(&mut out.coefficients, &INVERSE_TWIDDLES);
 for (value, &untwist) in out.coefficients.iter_mut().zip(&UNTWIST_SCALED) {
 *value = product(*value, untwist); }''',
'multiply_add_assign': '''for i in 0..N { self.values[i] = reduce_once(
 u32::from(self.values[i]) + u32::from(product(left.values[i], right.values[i])), ); }'''
}


def function_body(source, name):
    code=m.code_only(source)
    found = re.search(r'\bfn\s+'+name+r'\s*\(', code)
    m.require(found is not None, 'public schedule function absent')
    start = code.index('{', found.end())+1
    end, depth = start, 1
    while depth:
        m.require(end < len(code), 'unterminated source schedule')
        depth += (code[end] == '{') - (code[end] == '}'); end += 1
    return source[start:end-1]


def normalized(text):
    return re.sub(r'\s+', '', m.strip_comments(text))


def source_guard(source):
    expected = dict(PUBLIC_TEMPLATES, transform=TEMPLATE)
    for name, template in expected.items():
        m.require(normalized(function_body(source, name)) == normalized(template),
                  'checked source schedule template differs: '+name)
    for statement in (
        'const TWIST: [u16; N] = public_powers(PSI, 1);',
        'const UNTWIST_SCALED: [u16; N] = public_powers(PSI_INVERSE, N_INVERSE);',
        'const FORWARD_TWIDDLES: [u16; N - 1] = stage_twiddles(OMEGA);',
        'const INVERSE_TWIDDLES: [u16; N - 1] = stage_twiddles(OMEGA_INVERSE);'):
        m.require(normalized(statement) in normalized(m.code_only(source)), 'table construction tie differs')
    return {name: hashlib.sha256(normalized(template).encode()).hexdigest()
            for name, template in expected.items()}


def matrix(root, n, q, initial_scale=None, final_scale=None):
    # Each row is a formal linear combination of every input coefficient.
    values = [[(initial_scale[i] if initial_scale else 1) if i == j else 0 for j in range(n)] for i in range(n)]
    for i in range(n):
        rev = int(format(i, '08b')[::-1], 2)
        if i < rev: values[i], values[rev] = values[rev], values[i]
    for stage in range(8):
        length = 2 << stage; half = length >> 1
        twiddles = [pow(root, offset*n//length, q) for offset in range(half)]
        for start in range(0, n, length):
            for offset, twiddle in enumerate(twiddles):
                lo, hi = values[start+offset], values[start+offset+half]
                values[start+offset] = [(a+twiddle*b) % q for a, b in zip(lo, hi)]
                values[start+offset+half] = [(a-twiddle*b) % q for a, b in zip(lo, hi)]
    if final_scale:
        values = [[a*final_scale[i] % q for a in row] for i, row in enumerate(values)]
    return values


def build(source=None):
    p = m.Program(engine=source) if source is not None else m.Program()
    guard = source_guard(p.engine)
    c = {name: m.number(v.term) for name, v in p.env.items()}
    n, q, psi, omega = (c[name] for name in ('N', 'Q', 'PSI', 'OMEGA'))
    m.require(n == 256 and q == 7681, 'certificate profile changed')
    m.require(all(q % d for d in range(2, int(q**0.5)+1)), 'modulus not prime')
    m.require(pow(psi, n, q) == q-1 and pow(psi, 2*n, q) == 1 and pow(psi, 2, q) == omega,
              'negacyclic roots incorrect')
    m.require(pow(omega, n, q) == 1 and pow(omega, n//2, q) != 1, 'cyclic root not exact order')
    m.require(psi*c['PSI_INVERSE'] % q == 1 and omega*c['OMEGA_INVERSE'] % q == 1
              and n*c['N_INVERSE'] % q == 1, 'inverse constants differ')
    twist = [pow(psi, i, q) for i in range(n)]
    untwist = [c['N_INVERSE'] * pow(c['PSI_INVERSE'], i, q) % q for i in range(n)]
    forward = matrix(omega, n, q, initial_scale=twist)
    inverse = matrix(c['OMEGA_INVERSE'], n, q, final_scale=untwist)
    for k in range(n):
        for j in range(n):
            m.require(forward[k][j] == pow(psi*pow(omega, k, q) % q, j, q), 'formal forward coefficient differs')
            m.require(inverse[j][k] == untwist[j]*pow(c['OMEGA_INVERSE'], j*k, q) % q,
                      'formal inverse coefficient differs')
    sums = []
    for d in range(n):
        value = sum(pow(omega, d*k, q) for k in range(n)) % q
        m.require(value == (n if d == 0 else 0), 'orthogonality identity differs')
        sums.append(value)
    for k in range(n):
        m.require(pow(psi*pow(omega, k, q), n, q) == q-1, 'evaluation root not in X^N+1')
    encode = lambda a: hashlib.sha256(json.dumps(a, separators=(',', ':')).encode()).hexdigest()
    return dict(schema='m15-checked-schedule-ntt-algebra-certificate-v1', status='PASS_SCOPED',
                source_sha256=p.source_bindings(), schedule_templates_sha256=guard,
                instrument_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                translator_sha256=hashlib.sha256((HERE/'source_model.py').read_bytes()).hexdigest(),
                forward_matrix_sha256=encode(forward), inverse_matrix_sha256=encode(inverse),
                formal_linear_coefficients_checked=2*n*n, orthogonality_classes=n, evaluation_roots=n,
                linearity_induction_required_and_documented=True,
                universal_extension='all canonical polynomial inputs by linearity, inverse orthogonality and evaluation homomorphism',
                source_schedule_mapping_is_trusted_reviewed_template=True,
                Rust_or_compiler_semantics_formally_proved=False,
                constant_time_or_erasure_proved=False, C01_closed=False)


if __name__ == '__main__':
    path = HERE/'ntt-certificate-002.json'
    value = build()
    if len(sys.argv) > 1 and sys.argv[1] == 'verify':
        m.require(json.loads(path.read_text(encoding='utf-8')) == value, 'NTT certificate differs')
    else:
        with path.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps(dict(status=value['status'], checked_linear_coefficients=value['formal_linear_coefficients_checked'])))
