import os

import pytest

from cose.algorithms import EdDSA
from cose.curves import Ed448, Ed25519, X448, X25519
from cose.exceptions import CoseInvalidKey, CoseIllegalKeyType
from cose.keys import OKPKey, CoseKey
from cose.keys.keyops import SignOp
from cose.keys.keyparam import KpKty, OKPKpCurve, OKPKpX, OKPKpD, KpAlg, KpKeyOps

###############################################################
# OKP key checks
###############################################################
from cose.keys.keytype import KtyOKP, KtyEC2, KtySymmetric


def _is_valid_okp_key(key: OKPKey):
    check1 = (KpKty in key and OKPKpCurve in key) and (OKPKpX in key or OKPKpD in key)
    check2 = key[OKPKpCurve] in [X25519, X448, Ed25519, Ed448]

    return check2 and check1


@pytest.mark.parametrize('kty_attr, kty_value',
                         [(KpKty, KtyOKP), ('KTY', 'OKP'), (1, 1),
                          (KpKty, 'OKP'), (KpKty, 1),
                          ('KTY', KtyOKP), ('KTY', 1),
                          (1, KtyOKP), (1, 'OKP')])
@pytest.mark.parametrize('crv_attr, crv_value', [(OKPKpCurve, X25519), ('CURVE', X25519), (-1, X25519)])
@pytest.mark.parametrize('x_attr, x_value', [(OKPKpX, os.urandom(32)), ('X', os.urandom(32)), (-2, os.urandom(32))])
@pytest.mark.parametrize('d_attr, d_value', [(OKPKpD, os.urandom(32)), ('D', os.urandom(32)), (-4, os.urandom(32))])
def test_okp_keys_from_dicts(kty_attr, kty_value, crv_attr, crv_value, x_attr, x_value, d_attr, d_value):
    # The public and private values used in this test do not form a valid elliptic curve key,
    # but we don't care about that here

    d = {kty_attr: kty_value, crv_attr: crv_value, x_attr: x_value, d_attr: d_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_okp_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyOKP), ('KTY', 'OKP'), (1, 1)])
@pytest.mark.parametrize('crv_attr, crv_value', [(OKPKpCurve, Ed25519)])
@pytest.mark.parametrize('d_attr, d_value', [(OKPKpD, os.urandom(32)), ('D', os.urandom(32)), (-4, os.urandom(32))])
def test_okp_private_key_from_dicts(kty_attr, kty_value, crv_attr, crv_value, d_attr, d_value):
    # The public and private values used in this test do not form a valid elliptic curve key,
    # but we don't care about that here

    d = {kty_attr: kty_value, crv_attr: crv_value, d_attr: d_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_okp_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyOKP), ('KTY', 'OKP'), (1, 1)])
@pytest.mark.parametrize('crv_attr, crv_value', [(OKPKpCurve, Ed448), ('CURVE', Ed448), (-1, Ed448)])
@pytest.mark.parametrize('x_attr, x_value', [(OKPKpX, os.urandom(32)), ('X', os.urandom(32)), (-2, os.urandom(32))])
def test_okp_public_keys_from_dicts(kty_attr, kty_value, crv_attr, crv_value, x_attr, x_value):
    # The public and private values used in this test do not form a valid elliptic curve key,
    # but we don't care about that here

    d = {kty_attr: kty_value, crv_attr: crv_value, x_attr: x_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_okp_key(cose_key)


@pytest.mark.parametrize('crv', [X25519, X448, Ed25519, Ed448, 4, 'X25519', 'X448'])
def test_okp_key_generation_encoding_decoding(crv):
    trails = 256

    for i in range(trails):
        okp_test = OKPKey.generate_key(curve=crv)
        okp_encoded = okp_test.encode()
        okp_decoded = CoseKey.decode(okp_encoded)
        assert _is_valid_okp_key(okp_decoded)


@pytest.mark.parametrize('crv', [X25519, X448, Ed25519, Ed448, 'X25519', 4, 5])
def test_okp_key_generation(crv):
    key = OKPKey.generate_key(crv)

    assert _is_valid_okp_key(key)


@pytest.mark.parametrize('crv', [X25519, X448, Ed25519, Ed448])
def test_okp_key_construction(crv):
    key = OKPKey(crv=crv, x=os.urandom(32), d=os.urandom(32), optional_params={'ALG': 'EDDSA'})

    assert _is_valid_okp_key(key)

    serialized = key.encode()
    _ = CoseKey.decode(serialized)


@pytest.mark.parametrize('crv', [X25519, X448, Ed25519, Ed448])
def test_fail_on_missing_key_values(crv):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = OKPKey(crv=crv)

    assert "Either the public values or the private value must be specified" in str(excinfo.value)


def test_fail_on_missing_crv_attr():
    cose_key = {KpKty: KtyOKP, OKPKpX: os.urandom(32), OKPKpD: os.urandom(32)}

    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = CoseKey.from_dict(cose_key)

    assert "COSE OKP Key must have an OKPKpCurve attribute" in str(excinfo.value)


@pytest.mark.parametrize('crv', [X25519, X448, Ed25519, Ed448])
@pytest.mark.parametrize('kty', [KtyEC2, KtySymmetric, 2, 4])
def test_fail_on_illegal_kty(crv, kty):
    params = {KpKty: kty}

    with pytest.raises(CoseIllegalKeyType) as excinfo:
        _ = OKPKey(crv=crv, x=os.urandom(32), d=os.urandom(32), optional_params=params)

    assert "Illegal key type in OKP COSE Key" in str(excinfo.value)


def test_remove_empty_keyops_list():
    cose_key = {KpKty: KtyOKP, OKPKpD: os.urandom(16), KpAlg: EdDSA, OKPKpCurve: Ed25519, KpKeyOps: []}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps not in key


def test_existing_non_empty_keyops_list():
    cose_key = {KpKty: KtyOKP, OKPKpD: os.urandom(16), KpAlg: EdDSA, OKPKpCurve: Ed448, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps in key


def test_dict_operations_on_okp_key():
    cose_key = {KpKty: KtyOKP, OKPKpD: os.urandom(16), KpAlg: EdDSA, OKPKpCurve: Ed448, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKty in key
    assert OKPKpD in key
    assert OKPKpX not in key
    assert 1 in key
    assert -4 in key
    assert KpAlg in key
    assert 'ALG' in key
