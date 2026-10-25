"""Independent coefficient-domain R1 oracle, for synthetic tests only.

Python hashlib + NumPy integer convolution; no Rust arithmetic or engine imports.
This implementation does not claim constant time or secret memory erasure.
"""

import hashlib
import numpy as np

Q=7681
N=256
K=6
TAG=b'KEM1536-DEV-Q7681-R1\0'
VP=2496
EK=2528
DK=5088
CT=2656


def domain(label,*args):
    return TAG+label+b'\0'+b''.join(args)


def h(ek):
    return hashlib.sha3_256(domain(b'H',ek)).digest()


def g(label,*args):
    return hashlib.sha3_512(domain(label,*args)).digest()


def fallback(z,c):
    return hashlib.shake_256(domain(b'J',z,c)).digest(32)


def uniform(rho,i,j):
    sponge=hashlib.shake_128(domain(b'A',rho,bytes([i,j])))
    length=1024
    while True:
        raw=sponge.digest(length)
        candidates=np.frombuffer(raw,dtype='<u2').astype(np.int64)&8191
        accepted=candidates[candidates<Q]
        if len(accepted)>=N:
            return accepted[:N]
        length*=2


def noise(seed,nonce):
    raw=hashlib.shake_256(domain(b'N',seed,bytes([nonce]))).digest(192)
    bits=np.unpackbits(np.frombuffer(raw,dtype=np.uint8),bitorder='little').astype(np.int64).reshape(N,6)
    return (bits[:,:3].sum(axis=1)-bits[:,3:].sum(axis=1))%Q


def multiply(a,b):
    convolution=np.convolve(a,b)
    result=convolution[:N].copy()
    result[:N-1]-=convolution[N:]
    return result%Q


def pack(a,d):
    return sum(int(x)<<(d*i) for i,x in enumerate(a)).to_bytes(N*d//8,'little')


def unpack(raw,d):
    if len(raw)!=N*d//8:
        raise ValueError('polynomial length')
    value=int.from_bytes(raw,'little')
    return np.array([(value>>(d*i))&((1<<d)-1) for i in range(N)],dtype=np.int64)


def compress(a,d):
    return ((2*a*2**d+Q)//(2*Q))%2**d


def decompress(a,d):
    return (2*Q*a+2**d)//2**(d+1)


def vector(raw,strict=True):
    if len(raw)!=VP:
        raise ValueError('vector length')
    result=[unpack(raw[i*416:(i+1)*416],13) for i in range(K)]
    if strict and any(np.any(x>=Q) for x in result):
        raise ValueError('noncanonical vector')
    return [x%Q for x in result]


def public(raw):
    if len(raw)!=EK:
        raise ValueError('public length')
    vector(raw[:VP])
    return raw


def private(raw):
    if len(raw)!=DK:
        raise ValueError('private length')
    vector(raw[:VP])
    public(raw[VP:VP+EK])
    if h(raw[VP:VP+EK])!=raw[VP+EK:VP+EK+32]:
        raise ValueError('private hash')
    return raw


def keygen(d,z):
    if len(d)!=32 or len(z)!=32:
        raise ValueError('seed length')
    expanded=g(b'KG',d,b'\x06')
    rho,sigma=expanded[:32],expanded[32:]
    s=[noise(sigma,i) for i in range(K)]
    t=[(sum((multiply(uniform(rho,i,j),s[j]) for j in range(K)),np.zeros(N,dtype=np.int64))
        +noise(sigma,6+i))%Q for i in range(K)]
    ek=b''.join(pack(p,13) for p in t)+rho
    dk=b''.join(pack(p,13) for p in s)+ek+h(ek)+z
    return ek,dk


def encrypt(ek,m,seed):
    public(ek)
    t=vector(ek[:VP])
    rho=ek[VP:]
    r=[noise(seed,i) for i in range(K)]
    u=[(sum((multiply(uniform(rho,j,i),r[j]) for j in range(K)),np.zeros(N,dtype=np.int64))
        +noise(seed,6+i))%Q for i in range(K)]
    message=np.unpackbits(np.frombuffer(m,dtype=np.uint8),bitorder='little').astype(np.int64)
    v=(sum((multiply(t[i],r[i]) for i in range(K)),np.zeros(N,dtype=np.int64))
       +noise(seed,12)+decompress(message,1))%Q
    return b''.join(pack(p,13) for p in u)+pack(compress(v,5),5)


def decrypt(dk,c):
    if len(c)!=CT:
        raise ValueError('ciphertext length')
    s=vector(dk[:VP])
    u=vector(c[:VP],False)
    v=decompress(unpack(c[VP:],5),5)
    decoded=compress((v-sum((multiply(s[i],u[i]) for i in range(K)),np.zeros(N,dtype=np.int64)))%Q,1)
    return np.packbits(decoded.astype(np.uint8),bitorder='little').tobytes()


def encapsulate(ek,m):
    public(ek)
    if len(m)!=32:
        raise ValueError('message length')
    material=g(b'G',m,h(ek))
    return encrypt(ek,m,material[32:]),material[:32]


def decapsulate(dk,c):
    private(dk)
    if len(c)!=CT:
        raise ValueError('ciphertext length')
    ek=dk[VP:VP+EK]
    message=decrypt(dk,c)
    material=g(b'G',message,dk[VP+EK:VP+EK+32])
    cp=encrypt(ek,message,material[32:])
    # Test oracle only; application Rust API never returns this rejection flag.
    return (material[:32],True) if cp==c else (fallback(dk[-32:],c),False)


def synthetic_seeds(case):
    seed=hashlib.shake_256(domain(b'TEST',case.to_bytes(4,'little'))).digest(96)
    return seed[:32],seed[32:64],seed[64:]
