from coincurve.utils import int_to_bytes_padded
from ._libsecp256k1 import ffi, lib

import secrets


GROUP_ORDER_INT = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
INFINITY = bytes([0xC0]) + bytes(47)


def get_valid_secret(bits=252):
    # A key that secp256k1_bls_dleag_prove accepts: 2^16 <= key < 2^bits.
    if not 17 <= bits <= 252:
        raise ValueError('Invalid bits')
    return int_to_bytes_padded(2 ** 16 + secrets.randbelow(2 ** bits - 2 ** 16))


def _load_scalar(x):
    if len(x) != 32:
        raise ValueError('Invalid scalar length')
    sc = ffi.new('secp256k1_bls_scalar *')
    if lib.secp256k1_bls_scalar_set_b32(sc, x) != 1:
        raise ValueError('Invalid scalar')
    return sc


def _load_point(p):
    if len(p) != 48:
        raise ValueError('Invalid point length')
    pt = ffi.new('secp256k1_bls_point *')
    if lib.secp256k1_bls_point_parse(pt, p) != 1:
        raise ValueError('Invalid point')
    return pt


def _point_bytes(pt):
    output = ffi.new('unsigned char[48]')
    lib.secp256k1_bls_point_serialize(output, pt)
    return bytes(ffi.buffer(output, 48))


def bls12_381_get_pubkey(privkey):
    sc = _load_scalar(privkey)
    if lib.secp256k1_bls_scalar_is_zero(sc):
        raise ValueError('Invalid scalar')
    gen = _load_point(bytes(ffi.buffer(lib.secp256k1_bls_gen_a, 48)))
    pt = ffi.new('secp256k1_bls_point *')
    lib.secp256k1_bls_point_mul(pt, gen, sc)
    return _point_bytes(pt)


def bls12_381_scalar_add(x, y):
    sx = _load_scalar(x)
    sy = _load_scalar(y)
    sr = ffi.new('secp256k1_bls_scalar *')
    lib.secp256k1_bls_scalar_add(sr, sx, sy)
    output = ffi.new('unsigned char[32]')
    lib.secp256k1_bls_scalar_get_b32(output, sr)
    return bytes(ffi.buffer(output, 32))


def bls12_381_add(x, y):
    px = _load_point(x)
    py = _load_point(y)
    pr = ffi.new('secp256k1_bls_point *')
    lib.secp256k1_bls_point_add(pr, px, py)
    result = _point_bytes(pr)
    if result == INFINITY:
        raise ValueError('Result is the point at infinity')
    return result
