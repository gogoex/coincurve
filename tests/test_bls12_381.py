import pytest

from coincurve.utils import int_to_bytes_padded
from coincurve.bls12_381 import (
    GROUP_ORDER_INT,
    get_valid_secret,
    bls12_381_get_pubkey,
    bls12_381_scalar_add,
    bls12_381_add,
)

# k*G1, 48-byte compressed (standard BLS12-381 generator).
G1 = bytes.fromhex('97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb')
G1_2 = bytes.fromhex('a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e')
G1_3 = bytes.fromhex('89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224')


def test_bls12_381_pubkey():
    assert bls12_381_get_pubkey(int_to_bytes_padded(1)) == G1
    assert bls12_381_get_pubkey(int_to_bytes_padded(2)) == G1_2
    assert bls12_381_get_pubkey(int_to_bytes_padded(3)) == G1_3
    with pytest.raises(ValueError):
        bls12_381_get_pubkey(bytes(32))                              # zero
    with pytest.raises(ValueError):
        bls12_381_get_pubkey(int_to_bytes_padded(GROUP_ORDER_INT))   # r
    with pytest.raises(ValueError):
        bls12_381_get_pubkey(bytes(31))


def test_bls12_381_add():
    assert bls12_381_add(G1, G1_2) == G1_3
    a = get_valid_secret()
    b = get_valid_secret()
    # Combined key: (a + b)*G1 == a*G1 + b*G1
    assert bls12_381_get_pubkey(bls12_381_scalar_add(a, b)) == \
        bls12_381_add(bls12_381_get_pubkey(a), bls12_381_get_pubkey(b))
    minus_g = bls12_381_get_pubkey(int_to_bytes_padded(GROUP_ORDER_INT - 1))
    with pytest.raises(ValueError):
        bls12_381_add(G1, minus_g)                                   # infinity
    with pytest.raises(ValueError):
        bls12_381_add(G1, b'\xff' * 48)
    with pytest.raises(ValueError):
        bls12_381_add(G1, G1[:47])


def test_bls12_381_scalar_add():
    one = int_to_bytes_padded(1)
    r_minus_1 = int_to_bytes_padded(GROUP_ORDER_INT - 1)
    assert bls12_381_scalar_add(one, one) == int_to_bytes_padded(2)
    assert bls12_381_scalar_add(r_minus_1, int_to_bytes_padded(2)) == one   # wraps mod r
    with pytest.raises(ValueError):
        bls12_381_scalar_add(one, int_to_bytes_padded(GROUP_ORDER_INT))


def test_get_valid_secret():
    for _ in range(64):
        k = int.from_bytes(get_valid_secret(), 'big')
        assert 2 ** 16 <= k < 2 ** 252
    k = int.from_bytes(get_valid_secret(bits=17), 'big')
    assert 2 ** 16 <= k < 2 ** 17
    for bad in (16, 253):
        with pytest.raises(ValueError):
            get_valid_secret(bits=bad)


if __name__ == '__main__':
    pytest.main(['-s', __file__])
