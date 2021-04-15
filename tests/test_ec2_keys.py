import os

import pytest

from cose.algorithms import Es256
from cose.curves import P521, P384, P256
from cose.exceptions import CoseInvalidKey, CoseIllegalKeyType, CoseException
from cose.keys import EC2Key, CoseKey
from cose.keys.keyops import SignOp
from cose.keys.keyparam import KpKty, EC2KpCurve, EC2KpX, EC2KpY, EC2KpD, KpAlg, KpKeyOps
from cose.keys.keytype import KtyEC2, KtyOKP, KtySymmetric


###############################################################
# EC2 key checks
###############################################################


def _is_valid_ec2_key(key: EC2Key):
    check1 = (KpKty in key and EC2KpCurve in key) and ((EC2KpX in key and EC2KpY in key) or EC2KpD in key)
    check2 = key[EC2KpCurve] in [P256, P384, P521]

    return check2 and check1


@pytest.mark.parametrize('kty_attr, kty_value',
                         [(KpKty, KtyEC2), ('KTY', 'EC2'), (1, 2),
                          (KpKty, 'EC2'), (KpKty, 2),
                          ('KTY', KtyEC2), ('KTY', 2),
                          (1, KtyEC2), (1, 'EC2')])
@pytest.mark.parametrize('crv_attr, crv_value', [(EC2KpCurve, P256), ('CURVE', P256), (-1, P256)])
@pytest.mark.parametrize('x_attr, x_value', [(EC2KpX, os.urandom(32)), ('X', os.urandom(32)), (-2, os.urandom(32))])
@pytest.mark.parametrize('y_attr, y_value', [(EC2KpY, os.urandom(32)), ('Y', os.urandom(32)), (-3, os.urandom(32))])
@pytest.mark.parametrize('d_attr, d_value', [(EC2KpD, os.urandom(32)), ('D', os.urandom(32)), (-4, os.urandom(32))])
def test_ec2_keys_from_dicts(kty_attr, kty_value, crv_attr, crv_value, x_attr, x_value, y_attr, y_value, d_attr,
                             d_value):
    # The public and private values used in this test do not form a valid elliptic curve key,
    # but we don't care about that here

    d = {kty_attr: kty_value, crv_attr: crv_value, x_attr: x_value, y_attr: y_value, d_attr: d_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_ec2_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyEC2), ('KTY', 'EC2'), (1, 2)])
@pytest.mark.parametrize('crv_attr, crv_value', [(EC2KpCurve, P384)])
@pytest.mark.parametrize('d_attr, d_value', [(EC2KpD, os.urandom(32)), ('D', os.urandom(32)), (-4, os.urandom(32))])
def test_ec2_private_key_from_dicts(kty_attr, kty_value, crv_attr, crv_value, d_attr, d_value):
    # The public and private values used in this test do not form a valid elliptic curve key,
    # but we don't care about that here

    d = {kty_attr: kty_value, crv_attr: crv_value, d_attr: d_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_ec2_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyEC2), ('KTY', 'EC2'), (1, 2)])
@pytest.mark.parametrize('crv_attr, crv_value', [(EC2KpCurve, P521), ('CURVE', P521), (-1, P521)])
@pytest.mark.parametrize('x_attr, x_value', [(EC2KpX, os.urandom(32)), ('X', os.urandom(32)), (-2, os.urandom(32))])
@pytest.mark.parametrize('y_attr, y_value', [(EC2KpY, os.urandom(32)), ('Y', os.urandom(32)), (-3, os.urandom(32))])
def test_ec2_public_keys_from_dicts(kty_attr, kty_value, crv_attr, crv_value, x_attr, x_value, y_attr, y_value):
    # The public and private values used in this test do not form a valid elliptic curve key,
    # but we don't care about that here

    d = {kty_attr: kty_value, crv_attr: crv_value, x_attr: x_value, y_attr: y_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_ec2_key(cose_key)


@pytest.mark.parametrize('crv', [P256, P384, P521])
def test_ec2_key_generation_encoding_decoding(crv):
    trails = 256

    for i in range(trails):
        ec2_test = EC2Key.generate_key(crv=crv)
        ec2_encoded = ec2_test.encode()
        ec2_decoded = CoseKey.decode(ec2_encoded)
        assert _is_valid_ec2_key(ec2_decoded)


@pytest.mark.parametrize('crv', [P256, P384, P521, 'P_256', 'P_384', 'P_521', 1, 2, 3])
def test_ec2_key_generation(crv):
    key = EC2Key.generate_key(crv)

    assert _is_valid_ec2_key(key)


@pytest.mark.parametrize('crv', [P256, P384, P521, 'P_256', 'P_384', 1, 2])
def test_ec2_key_construction(crv):
    key = EC2Key(crv=crv, x=os.urandom(32), y=os.urandom(32), d=os.urandom(32))

    assert _is_valid_ec2_key(key)


@pytest.mark.parametrize('crv', [P256, P384, P521])
def test_fail_on_missing_key_values(crv):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = EC2Key(crv=crv)

    assert "Either the public values or the private value must be specified" in str(excinfo.value)


@pytest.mark.parametrize('crv', [P256, P384, P521])
def test_fail_on_missing_key_values_from_dict(crv):
    d = {'KTY': 'EC2', 'CURVE': 'P_384'}

    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = CoseKey.from_dict(d)

    assert "Either the public values or the private value must be specified" in str(excinfo.value)


@pytest.mark.parametrize('crv', [P256, P384, P521])
def test_fail_on_missing_public_y_values(crv):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = EC2Key(crv=crv, x=os.urandom(32))

    assert "Missing public coordinate X/Y" in str(excinfo.value)


@pytest.mark.parametrize('crv', [P256, P384, P521])
def test_fail_on_missing_public_x_values(crv):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = EC2Key(crv=crv, y=os.urandom(32))

    assert "Missing public coordinate X/Y" in str(excinfo.value)


@pytest.mark.parametrize('crv', [P256, P384, P521])
def test_fail_with_d_and_missing_public_x_values(crv):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = EC2Key(crv=crv, y=os.urandom(32), d=os.urandom(32))

    assert "Missing public coordinate X/Y" in str(excinfo.value)


@pytest.mark.parametrize('crv', [P256, P384, P521])
def test_fail_with_d_and_missing_public_y_values(crv):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = EC2Key(crv=crv, x=os.urandom(32), d=os.urandom(32))

    assert "Missing public coordinate X/Y" in str(excinfo.value)


def test_fail_on_missing_crv_attr():
    cose_key = {KpKty: KtyEC2, EC2KpX: os.urandom(32), EC2KpY: os.urandom(32)}

    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = CoseKey.from_dict(cose_key)

    assert "COSE EC2 Key must have an EC2KpCurve attribute" in str(excinfo.value)


@pytest.mark.parametrize('crv', [P256, P384, P521])
@pytest.mark.parametrize('kty', [KtyOKP, KtySymmetric, 1, 4])
def test_fail_on_illegal_kty(crv, kty):
    params = {KpKty: kty}

    with pytest.raises(CoseIllegalKeyType) as excinfo:
        _ = EC2Key(crv=crv, x=os.urandom(32), y=os.urandom(32), d=os.urandom(32), optional_params=params)

    assert "Illegal key type in EC2 COSE Key" in str(excinfo.value)


def test_remove_empty_keyops_list():
    cose_key = {KpKty: KtyEC2, EC2KpD: os.urandom(32), KpAlg: Es256, EC2KpCurve: P256, KpKeyOps: []}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps not in key


def test_existing_non_empty_keyops_list():
    cose_key = {KpKty: KtyEC2, EC2KpD: os.urandom(32), KpAlg: Es256, EC2KpCurve: P256, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps in key


def test_dict_operations_on_ec2_key():
    cose_key = {KpKty: KtyEC2, EC2KpD: os.urandom(32), KpAlg: Es256, EC2KpCurve: P256, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKty in key
    assert EC2KpD in key
    assert EC2KpX not in key
    assert 1 in key
    assert 3 in key
    assert KpAlg in key
    assert 'ALG' in key

    del key['ALG']

    key['subject_name'] = 'verifying key'
    assert 'subject_name' in key

    assert 'ALG' not in key


def test_dict_valid_deletion():
    cose_key = {
        KpKty: KtyEC2,
        EC2KpD: os.urandom(32),
        EC2KpX: os.urandom(32),
        EC2KpY: os.urandom(32),
        KpAlg: Es256,
        EC2KpCurve: P256,
        KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)
    del key[KpAlg]
    assert KpAlg not in key

    key = CoseKey.from_dict(cose_key)
    del key[3]
    assert KpAlg not in key

    key = CoseKey.from_dict(cose_key)
    del key[EC2KpD]
    assert EC2KpD not in key

    key = CoseKey.from_dict(cose_key)
    del key[-4]
    assert EC2KpD not in key

    key = CoseKey.from_dict(cose_key)
    del key[EC2KpY]
    assert EC2KpY not in key
    assert EC2KpX not in key


def test_dict_invalid_deletion():
    cose_key = {
        KpKty: KtyEC2,
        EC2KpD: os.urandom(32),
        EC2KpX: os.urandom(32),
        EC2KpY: os.urandom(32),
        KpAlg: Es256,
        EC2KpCurve: P256,
        KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)
    del key[EC2KpY]
    assert EC2KpY not in key
    assert EC2KpX not in key

    with pytest.raises(CoseInvalidKey) as excinfo:
        del key[EC2KpD]

    assert "Deleting <class 'cose.keys.keyparam.EC2KpD'> attribute would lead to an invalid COSE EC2 Key" in str(
        excinfo.value)


def test_set_curve_in_key():
    with pytest.raises(CoseException) as excinfo:
        key = EC2Key(crv='P257', d=os.urandom(32))

    assert "Unknown COSE header or key attribute" in str(excinfo)

    with pytest.raises(CoseException) as excinfo:
        key = EC2Key(crv='Ed25519', d=os.urandom(32))

    assert "Unknown COSE header or key attribute" in str(excinfo)

    key = EC2Key(crv='P_256', d=os.urandom(32))
    assert key.crv == P256


def test_unknown_key_attribute():
    key = EC2Key(crv='P_256', d=os.urandom(32), optional_params={"subject_name": "signing key"})

    assert "subject_name" in key
    assert key['subject_name'] == "signing key"
