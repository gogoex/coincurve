from coincurve.context import GLOBAL_CONTEXT
from ._libsecp256k1 import ffi, lib
import secrets

# The library treats n_bits outside [1, 252] as an illegal argument, which
# aborts the process with the default callback; reject it here instead.
MAX_BITS = 252


def _check_bits(bits):
    if not 1 <= bits <= MAX_BITS:
        raise ValueError('Invalid bits')


def bls_dleag_proof_len(bits=252):
    return lib.secp256k1_bls_dleag_size(bits)


def get_nonce():
    return secrets.token_bytes(32)


def bls_dleag_prove(private_key, nonce_bytes=None, bits=252, context=GLOBAL_CONTEXT):
    # Proves that private_key is the discrete log of both private_key*G on
    # secp256k1 and private_key*G1 on BLS12-381. The key must fit in `bits`
    # bits (for 252: 2^16 <= key < 2^252), otherwise proving fails.
    _check_bits(bits)
    if nonce_bytes is None:
        nonce_bytes = get_nonce()
    elif len(nonce_bytes) != 32:
        raise ValueError('Invalid nonce length')

    proof_length = bls_dleag_proof_len(bits)
    proof_output = ffi.new('unsigned char[{}]'.format(proof_length))

    proof_length_p = ffi.new('size_t *')
    proof_length_p[0] = proof_length

    rv = lib.secp256k1_bls_dleag_prove(
        context.ctx,
        proof_output,
        proof_length_p,
        private_key.secret,
        bits,
        nonce_bytes,
    )

    if rv != 1:
        raise ValueError('secp256k1_bls_dleag_prove failed')

    return bytes(ffi.buffer(proof_output, proof_length_p[0]))


def bls_dleag_verify(proof, bits=252, context=GLOBAL_CONTEXT):
    _check_bits(bits)
    proof_bytes = ffi.from_buffer(proof)
    proof_length = len(proof)

    rv = lib.secp256k1_bls_dleag_verify(
        context.ctx,
        proof_bytes,
        proof_length,
        bits,
    )

    return True if rv == 1 else False


def verify_bls_point(pubkey_bytes, context=GLOBAL_CONTEXT):
    if len(pubkey_bytes) != 48:
        raise ValueError('Invalid pubkey length')

    rv = lib.secp256k1_bls_dleag_verify_bls_point(
        context.ctx,
        pubkey_bytes
    )

    return True if rv == 1 else False
