import pytest

from coincurve.keys import PrivateKey
from coincurve.bls12_381 import get_valid_secret, bls12_381_get_pubkey
from coincurve.dleag_bls import (
    bls_dleag_proof_len,
    bls_dleag_prove,
    bls_dleag_verify,
    verify_bls_point,
)


def test_bls_dleag():
    key = get_valid_secret()
    vk = PrivateKey(key)
    proof = bls_dleag_prove(vk)
    assert len(proof) == bls_dleag_proof_len() == 52957
    assert bls_dleag_verify(proof) is True
    # Embedded pubkeys: secp256k1 key*G and BLS12-381 key*G1.
    assert proof[0:33] == vk.public_key.format()
    assert proof[33:81] == bls12_381_get_pubkey(key)
    assert verify_bls_point(proof[33:81]) is True


def test_bls_dleag_nonce():
    vk = PrivateKey(get_valid_secret())
    nonce = bytes(range(32))
    p1 = bls_dleag_prove(vk, nonce_bytes=nonce)
    p2 = bls_dleag_prove(vk, nonce_bytes=nonce)
    p3 = bls_dleag_prove(vk, nonce_bytes=bytes(32))
    assert p1 == p2
    assert p1 != p3
    assert p1[:81] == p3[:81]
    with pytest.raises(ValueError):
        bls_dleag_prove(vk, nonce_bytes=bytes(31))


def test_bls_dleag_key_range():
    # Keys must satisfy 2^16 <= key < 2^252.
    with pytest.raises(ValueError):
        bls_dleag_prove(PrivateKey(b'\x10' + bytes(31)))      # 2^252
    with pytest.raises(ValueError):
        bls_dleag_prove(PrivateKey(bytes(30) + b'\xff\xff'))  # 2^16 - 1
    proof = bls_dleag_prove(PrivateKey(bytes(29) + b'\x01' + bytes(2)))  # 2^16
    assert bls_dleag_verify(proof) is True


def test_bls_dleag_bits():
    vk = PrivateKey(get_valid_secret(bits=64))
    proof = bls_dleag_prove(vk, bits=64)
    assert len(proof) == bls_dleag_proof_len(64)
    assert bls_dleag_verify(proof, bits=64) is True
    assert bls_dleag_verify(proof, bits=252) is False
    for bad in (0, 253):
        with pytest.raises(ValueError):
            bls_dleag_prove(vk, bits=bad)
        with pytest.raises(ValueError):
            bls_dleag_verify(proof, bits=bad)


def test_bls_dleag_tampered():
    proof = bytearray(bls_dleag_prove(PrivateKey(get_valid_secret())))
    assert bls_dleag_verify(bytes(proof[:-1])) is False
    proof[-1] ^= 1
    assert bls_dleag_verify(bytes(proof)) is False


def test_verify_bls_point():
    with pytest.raises(ValueError):
        verify_bls_point(bytes(47))
    assert verify_bls_point(b'\xff' * 48) is False
    assert verify_bls_point(b'\xc0' + bytes(47)) is False  # infinity
    assert verify_bls_point(b'\x80' + bytes(47)) is False  # on curve, order 3


if __name__ == '__main__':
    pytest.main(['-s', __file__])
