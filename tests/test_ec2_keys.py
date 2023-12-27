from binascii import unhexlify

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from pycose.algorithms import Es256
from pycose.keys.curves import P521, P384, P256
from pycose.exceptions import CoseInvalidKey, CoseIllegalKeyType, CoseException, CoseUnsupportedCurve
from pycose.keys import EC2Key, CoseKey
from pycose.keys.keyops import SignOp
from pycose.keys.keyparam import KpKty, EC2KpCurve, EC2KpX, EC2KpY, EC2KpD, KpAlg, KpKeyOps
from pycose.keys.keytype import KtyEC2, KtyOKP, KtySymmetric

p256_d = unhexlify(b'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3')
p256_x = unhexlify(b'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff')
p256_y = unhexlify(b'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e')

p384_d = unhexlify(b'bc8e754b8305df8fec9bfbf7fc257810d43a94a8b76947a8d528ede4337654c6526aec4260070b97966958da4bf97f25')
p384_x = unhexlify(b'9e5584a68345d7d7e5474ce79966b6b1dbc6496cd7fcdccf772effa961ab71812101db158114e58d898bba29d96b6323')
p384_y = unhexlify(b'650b3b83c1251aa745625048253fcc33255e522c5cf965637de3100075e51999443db22a9588e1c9dd8a23861043149f')

p521_y = unhexlify(b'01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d69090080'
                   b'33ebc10ac999b9d7f5cc2519f3fe1ea1d9475')
p521_d = unhexlify(
    b'00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e'
    b'84ca2c3609fdf177feb26d')
p521_x = unhexlify(
    b'0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbca'
    b'd0f2457620085e5c8f42ad')


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
@pytest.mark.parametrize('x_attr, x_value', [(EC2KpX, p256_x), ('X', p256_x), (-2, p256_x)])
@pytest.mark.parametrize('y_attr, y_value', [(EC2KpY, p256_y), ('Y', p256_y), (-3, p256_y)])
@pytest.mark.parametrize('d_attr, d_value', [(EC2KpD, p256_d), ('D', p256_d), (-4, p256_d)])
def test_ec2_keys_from_dicts(kty_attr, kty_value, crv_attr, crv_value, x_attr, x_value, y_attr, y_value, d_attr,
                             d_value):
    dct = {kty_attr: kty_value, crv_attr: crv_value, x_attr: x_value, y_attr: y_value, d_attr: d_value}
    cose_key = CoseKey.from_dict(dct)
    assert _is_valid_ec2_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyEC2), ('KTY', 'EC2'), (1, 2)])
@pytest.mark.parametrize('crv_attr, crv_value', [(EC2KpCurve, P256)])
@pytest.mark.parametrize('d_attr, d_value', [(EC2KpD, p256_d), ('D', p256_d), (-4, p256_d)])
def test_ec2_private_key_from_dicts(kty_attr, kty_value, crv_attr, crv_value, d_attr, d_value):
    dct = {kty_attr: kty_value, crv_attr: crv_value, d_attr: d_value}
    cose_key = CoseKey.from_dict(dct)
    assert _is_valid_ec2_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyEC2), ('KTY', 'EC2'), (1, 2)])
@pytest.mark.parametrize('crv_attr, crv_value', [(EC2KpCurve, P521), ('CURVE', P521), (-1, P521)])
@pytest.mark.parametrize('x_attr, x_value', [(EC2KpX, p521_x), ('X', p521_x), (-2, p521_x)])
@pytest.mark.parametrize('y_attr, y_value', [(EC2KpY, p521_y), ('Y', p521_y), (-3, p521_y)])
def test_ec2_public_keys_from_dicts(kty_attr, kty_value, crv_attr, crv_value, x_attr, x_value, y_attr, y_value):
    dct = {kty_attr: kty_value, crv_attr: crv_value, x_attr: x_value, y_attr: y_value}
    cose_key = CoseKey.from_dict(dct)
    assert _is_valid_ec2_key(cose_key)


def test_ec2_private_key_from_pem():
    from_bstr = lambda enc: int.from_bytes(enc, byteorder='big')
    pub_nums = ec.EllipticCurvePublicNumbers(from_bstr(p256_x), from_bstr(p256_y), ec.SECP256R1())
    priv_nums = ec.EllipticCurvePrivateNumbers(from_bstr(p256_d), pub_nums)
    private_key = priv_nums.private_key()
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    cose_key = CoseKey.from_pem_private_key(pem)
    assert _is_valid_ec2_key(cose_key)


def test_ec2_public_key_from_pem():
    from_bstr = lambda enc: int.from_bytes(enc, byteorder='big')
    pub_nums = ec.EllipticCurvePublicNumbers(from_bstr(p256_x), from_bstr(p256_y), ec.SECP256R1())
    public_key = pub_nums.public_key()
    pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    cose_key = CoseKey.from_pem_public_key(pem)
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


@pytest.mark.parametrize('crv, x, y, d', [
    (P256, p256_x, p256_y, p256_d),
    (P384, p384_x, p384_y, p384_d),
    (P521, p521_x, p521_y, p521_d),
    ('P_256', p256_x, p256_y, p256_d),
    ('P_384', p384_x, p384_y, p384_d),
    (1, p256_x, p256_y, p256_d),
    (2, p384_x, p384_y, p384_d)
])
def test_ec2_key_construction(crv, x, y, d):
    key = EC2Key(crv=crv, x=x, y=y, d=d)

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


@pytest.mark.parametrize('crv, y', [(P256, p256_y), (P384, p384_y), (P521, p521_y)])
def test_fail_on_missing_public_x_values(crv, y):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = EC2Key(crv=crv, y=y)

    assert "Missing public coordinate X" in str(excinfo.value)


@pytest.mark.parametrize('crv, x', [(P256, p256_x), (P384, p384_x), (P521, p521_x)])
def test_on_missing_public_y_values(crv, x):
    key = EC2Key(crv=crv, x=x)

    assert key.y


@pytest.mark.parametrize('crv, y, d', [(P256, p256_y, p256_d), (P384, p384_y, p384_d), (P521, p521_y, p521_d)])
def test_with_d_and_missing_public_x_values(crv, y, d):
    key = EC2Key(crv=crv, y=y, d=d)

    assert key.x


@pytest.mark.parametrize('crv, x, d', [(P256, p256_x, p256_d), (P521, p521_x, p521_d)])
def test_fail_with_d_and_missing_public_y_values(crv, x, d):
    key = EC2Key(crv=crv, x=x, d=d)

    assert key.y


def test_fail_on_missing_crv_attr():
    cose_key = {KpKty: KtyEC2, EC2KpX: p256_x, EC2KpY: p256_y}

    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = CoseKey.from_dict(cose_key)

    assert "COSE curve cannot be None" in str(excinfo.value)


@pytest.mark.parametrize('crv', [P256])
@pytest.mark.parametrize('kty', [KtyOKP, KtySymmetric, 1, 4])
def test_fail_on_illegal_kty(crv, kty):
    params = {KpKty: kty}

    # NOTE: the stuff in params will override the parameters of the function if they are specified twice
    # Here the KpKty value which is set by the constructor gets overwritten by the params dict
    with pytest.raises(CoseIllegalKeyType) as excinfo:
        _ = EC2Key(crv=crv, x=p256_x, y=p256_y, d=p256_d, optional_params=params)

    assert "Illegal key type in EC2 COSE Key" in str(excinfo.value)


def test_remove_empty_keyops_list():
    cose_key = {KpKty: KtyEC2, EC2KpD: p384_d, KpAlg: Es256, EC2KpCurve: P256, KpKeyOps: []}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps not in key


def test_existing_non_empty_keyops_list():
    cose_key = {KpKty: KtyEC2, EC2KpD: p256_d, KpAlg: Es256, EC2KpCurve: P256, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps in key


def test_dict_operations_on_ec2_key():
    cose_key = {KpKty: KtyEC2, EC2KpX: p256_x, KpAlg: Es256, EC2KpCurve: P256, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKty in key
    assert EC2KpD not in key
    assert EC2KpY in key
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
        EC2KpD: p256_d,
        EC2KpX: p256_x,
        EC2KpY: p256_y,
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
        EC2KpD: p256_d,
        EC2KpX: p256_x,
        EC2KpY: p256_y,
        KpAlg: Es256,
        EC2KpCurve: P256,
        KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)
    del key[EC2KpY]
    assert EC2KpY not in key
    assert EC2KpX not in key

    with pytest.raises(CoseInvalidKey) as excinfo:
        del key[EC2KpD]

    assert "Deleting <class 'pycose.keys.keyparam.EC2KpD'> attribute would lead to an invalid COSE EC2 Key" in str(
        excinfo.value)


def test_set_curve_in_key():
    with pytest.raises(CoseException) as excinfo:
        _ = EC2Key(crv='P257', d=p256_d)

    assert "Unknown COSE attribute with value: [CoseCurve - P257]" in str(excinfo)

    with pytest.raises(CoseUnsupportedCurve) as excinfo:
        _ = EC2Key(crv='Ed25519', d=p256_d)

    assert "Invalid COSE curve <class 'pycose.keys.curves.Ed25519'> for key type EC2Key" in str(excinfo)

    key = EC2Key(crv='P_256', d=p256_d)
    assert key.crv == P256


def test_unknown_key_attribute():
    key = EC2Key(crv='P_256', d=p256_d, optional_params={"subject_name": "signing key"})

    assert "subject_name" in key
    assert key['subject_name'] == "signing key"

    k = key.encode()

    decoded_key = CoseKey.decode(k)

    assert decoded_key['subject_name'] == "signing key"


