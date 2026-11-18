"""Fail-closed translation of the used straight-line unsigned Rust subset.

The parser reads function bodies and constants from captured production
bytes. It is not a Rust compiler: unsupported syntax/types are rejected.
Nonwrapping arithmetic records a safety obligation; wrapping arithmetic
and casts use exact finite-width semantics. Logical shifts are unsigned.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import sys

RAW_LITERAL=re.compile(r'(?:br|r)(#*)"')
CHAR_LITERAL=re.compile(r"(?:b)?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|[^\r\n])|[^'\\\r\n])'")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / '.tools/m15-proof/site-packages'))
import z3


def require(ok, text):
    if not ok:
        raise ValueError(text)


def lexical(text, mask_strings=False):
    """Preserve offsets while excluding comments and optionally literals.

    Block comments are outside this restricted source input. Normal/raw
    strings and single character literals cannot introduce fake fn/const
    selectors or alter brace balancing. Lifetimes are not character literals.
    """
    require('/*' not in text, 'block comments outside supported subset')
    output=list(text);i=0
    def blank(start,end):
        for k in range(start,end):
            if output[k] not in ('\n','\r'):output[k]=' '
    while i<len(text):
        if text.startswith('//',i):
            end=text.find('\n',i)
            if end<0:end=len(text)
            blank(i,end);i=end;continue
        raw=RAW_LITERAL.match(text,i) if i==0 or not (text[i-1].isalnum() or text[i-1]=='_') else None
        if raw:
            closing='"'+raw[1];end=text.find(closing,raw.end())
            require(end>=0,'unterminated raw source string');end+=len(closing)
            if mask_strings:blank(i,end)
            i=end;continue
        if text[i]=='"':
            end=i+1
            while end<len(text):
                if text[end]=='\\':end+=2;continue
                if text[end]=='"':break
                end+=1
            require(end<len(text),'unterminated source string');end+=1
            if mask_strings:blank(i,end)
            i=end;continue
        char=CHAR_LITERAL.match(text,i)
        if char:
            end=char.end()
            if mask_strings:blank(i,end)
            i=end;continue
        i+=1
    return ''.join(output)


def strip_comments(text):
    return lexical(text)


def code_only(text):
    return lexical(text,mask_strings=True)


def body(source, name):
    code=code_only(source)
    match = re.search(r'\bfn\s+' + re.escape(name) + r'\s*\(([^)]*)\)\s*->\s*(u\d+)\s*\{', code)
    require(match is not None, 'straight-line signature absent: ' + name)
    start = match.end()
    depth, end = 1, start
    while depth:
        require(end < len(code), 'unterminated function')
        depth += (code[end] == '{') - (code[end] == '}')
        end += 1
    params = []
    for item in match.group(1).split(','):
        if item.strip():
            pair = re.fullmatch(r'\s*(\w+)\s*:\s*(u\d+|usize)\s*', item)
            require(pair is not None, 'parameter type not supported')
            params.append((pair[1], width(pair[2])))
    return params, width(match[2]), source[start:end-1]


def width(type_name):
    if type_name == 'usize':
        return 64  # This source model is explicitly the captured Windows x64 ABI.
    require(re.fullmatch(r'u(8|16|32|64|128)', type_name) is not None, 'unsupported unsigned type')
    return int(type_name[1:])


TOKEN = re.compile(r'\s*(::|>>|<<|[A-Za-z_]\w*|[0-9][0-9_]*(?:u\d+)?|[()+*/%&|^.,-])')


def tokens(text):
    out, pos = [], 0
    while pos < len(text):
        if not text[pos:].strip():
            break
        found = TOKEN.match(text, pos)
        require(found is not None, 'unsupported expression token near: ' + text[pos:pos+24])
        out.append(found[1]); pos = found.end()
    return out


@dataclass
class Value:
    term: object
    bits: object


def number(term):
    item = z3.simplify(term)
    require(z3.is_int_value(item), 'constant count required in restricted subset')
    return item.as_long()


class Parser:
    precedence = {'|': 1, '^': 2, '&': 3, '<<': 4, '>>': 4, '+': 5, '-': 5, '*': 6, '/': 6, '%': 6}

    def __init__(self, text, env, functions, obligations):
        self.items, self.i = tokens(text), 0
        self.env, self.functions, self.obligations = env, functions, obligations

    def pop(self, expected=None):
        require(self.i < len(self.items), 'unexpected end of expression')
        value = self.items[self.i]; self.i += 1
        require(expected is None or value == expected, 'unexpected expression token')
        return value

    def peek(self):
        return self.items[self.i] if self.i < len(self.items) else None

    def expression(self, minimum=0):
        item = self.pop()
        if item == '(':
            left = self.expression(); self.pop(')')
        elif re.fullmatch(r'[0-9][0-9_]*(?:u\d+)?', item):
            m = re.fullmatch(r'([0-9_]+?)(?:_?(u\d+))?', item)
            left = Value(z3.IntVal(int(m[1].replace('_', ''))), width(m[2]) if m[2] else None)
        elif item in ('u8', 'u16', 'u32', 'u64', 'u128') and self.peek() == '::':
            self.pop('::'); self.pop('from'); self.pop('(')
            arg = self.expression(); self.pop(')')
            require(arg.bits is not None and width(item) >= arg.bits, 'from must be a widening conversion')
            left = Value(arg.term, width(item))
        elif self.peek() == '(':
            self.pop('('); args = []
            while self.peek() != ')':
                args.append(self.expression())
                if self.peek() != ')': self.pop(',')
            self.pop(')')
            require(item in self.functions, 'unknown source function: ' + item)
            left = self.functions[item](args, self.obligations)
        else:
            require(item in self.env, 'unbound source identifier: ' + item)
            left = self.env[item]
        while True:
            op = self.peek()
            if op == '.' and minimum <= 9:
                self.pop('.'); method = self.pop(); self.pop('(')
                right = self.expression(); self.pop(')')
                require(method in ('wrapping_sub', 'wrapping_add') and left.bits is not None,
                        'unsupported unsigned method')
                self.match(left, right)
                raw = left.term - right.term if method == 'wrapping_sub' else left.term + right.term
                left = Value(raw % (1 << left.bits), left.bits)
            elif op == 'as' and minimum <= 8:
                self.pop('as'); b = width(self.pop())
                left = Value(left.term % (1 << b), b)
            elif op in self.precedence and self.precedence[op] >= minimum:
                self.pop(); right = self.expression(self.precedence[op] + 1)
                left = self.binary(op, left, right)
            else:
                break
        return left

    @staticmethod
    def match(left, right):
        if left.bits is None and right.bits is None: left.bits = right.bits = 32
        elif left.bits is None: left.bits = right.bits
        elif right.bits is None: right.bits = left.bits
        require(left.bits == right.bits, 'incompatible unsigned operands')

    def binary(self, op, left, right):
        if op in ('<<', '>>'):
            # All unsuffixed shifted literals in this accepted subset occur
            # in the u32 compression/decompression expressions. Their Rust
            # surrounding type is checked again by binary operand matching.
            if left.bits is None:
                left.bits = 32
            amount = number(right.term)
            self.obligations.append(z3.BoolVal(0 <= amount < left.bits))
            term = (left.term * (1 << amount)) % (1 << left.bits) if op == '<<' else left.term / (1 << amount)
            return Value(term, left.bits)
        self.match(left, right)
        a, b, bits = left.term, right.term, left.bits
        if op in ('+', '-', '*'):
            raw = {'+': lambda: a+b, '-': lambda: a-b, '*': lambda: a*b}[op]()
            self.obligations.append(z3.And(raw >= 0, raw < (1 << bits)))
            return Value(raw, bits)
        if op in ('/', '%'):
            self.obligations.append(b > 0)
            return Value(a/b if op == '/' else a % b, bits)
        if op == '&':
            # Compress uses a low-bit mask. Other masks are deliberately rejected.
            mask = number(b)
            require(mask >= 0 and ((mask + 1) & mask) == 0, 'only a constant low-bit mask is supported')
            return Value(a % (mask + 1), bits)
        raise ValueError('unsupported binary expression: ' + op)


def expression(text, env, functions, obligations):
    parser = Parser(text, dict(env), functions, obligations)
    value = parser.expression()
    require(parser.peek() is None, 'trailing source expression')
    return value


def constants(source):
    env = {}
    for name, type_name, text in re.findall(r'const\s+(N|Q|RECIP32|RECIP64|PSI|OMEGA|PSI_INVERSE|OMEGA_INVERSE|N_INVERSE)\s*:\s*(u\d+|usize)\s*=\s*([^;]+);', code_only(source)):
        checks = []
        result = expression(strip_comments(text), env, {}, checks)
        require(all(z3.is_true(z3.simplify(c)) for c in checks), 'public constant overflow')
        value = number(result.term)
        require(0 <= value < (1 << width(type_name)), 'constant outside type')
        env[name] = Value(z3.IntVal(value), width(type_name))
    require(set(env) == {'N', 'Q', 'RECIP32', 'RECIP64', 'PSI', 'OMEGA', 'PSI_INVERSE', 'OMEGA_INVERSE', 'N_INVERSE'},
            'constant set changed')
    return env


class Program:
    def __init__(self, engine=None, kem=None):
        self.engine = engine if engine is not None else (ROOT / 'crates/kem1536/src/engine_poly.rs').read_text(encoding='utf-8')
        self.kem = kem if kem is not None else (ROOT / 'crates/kem1536/src/dev_kem.rs').read_text(encoding='utf-8')
        self.env = constants(self.engine)
        local_q = re.findall(r'\bpub\s+const\s+Q\s*:\s*(u\d+)\s*=\s*(\d+)\s*;', code_only(self.kem))
        require(len(local_q) == 1 and width(local_q[0][0]) == self.env['Q'].bits
                and int(local_q[0][1]) == number(self.env['Q'].term),
                'KEM and arithmetic Q/type must agree in the actual sources')
        imports = re.findall(r'use\s+crate::engine_poly::\{([^}]*)\}\s*;', code_only(self.kem), flags=re.S)
        require(len(imports) == 1, 'arithmetic import binding changed')
        members = [re.sub(r'\s+', ' ', item.strip()) for item in imports[0].split(',')]
        require(members.count('quotient') == 1 and members.count('reduce_once') == 1,
                'compression arithmetic names must refer to the translated source functions')
        self.sources = {n: self.engine for n in ('reduce_once', 'quotient', 'product', 'reduce_wide')}
        self.sources.update({n: self.kem for n in ('compress', 'decompress')})
        self.functions = {n: self.function(n) for n in self.sources}

    def function(self, name):
        def invoke(args, obligations):
            params, result_bits, raw = body(self.sources[name], name)
            require(len(args) == len(params), 'source arity differs')
            env = dict(self.env)
            for (argname, bits), value in zip(params, args):
                require(value.bits == bits, 'source argument width differs')
                env[argname] = value
            clean = strip_comments(raw)
            parts = clean.split(';')
            for statement in parts[:-1]:
                match = re.fullmatch(r'\s*let\s+(\w+)\s*=\s*(.+)\s*', statement, flags=re.S)
                require(match is not None, 'only straight-line let statements supported')
                env[match[1]] = expression(match[2], env, self.functions, obligations)
            value = expression(parts[-1], env, self.functions, obligations)
            require(value.bits == result_bits, 'source return type differs')
            return value
        return invoke

    def call(self, name, args):
        obligations = []
        result = self.functions[name](args, obligations)
        return result, obligations

    def source_bindings(self):
        return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                ('crates/kem1536/src/engine_poly.rs', 'crates/kem1536/src/dev_kem.rs')}
