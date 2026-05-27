import os
import sys
from binascii import unhexlify

import pytest

from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from pycose.algorithms import MlDsa44, MlDsa65, MlDsa87
from pycose.exceptions import CoseInvalidKey, CoseIllegalKeyType, CoseIllegalKeyOps
from pycose.keys import AKPKey, CoseKey
from pycose.keys.keyops import SignOp, MacVerifyOp
from pycose.keys.keyparam import KpKty, AKPKpPub, AKPKpPriv, KpAlg, KpKeyOps
###############################################################
# AKP key checks
###############################################################
from pycose.keys.keytype import KtyAKP, KtyEC2, KtySymmetric


def _is_valid_akp_key(key: AKPKey):
    check1 = (KpKty in key and KpAlg in key) and (AKPKpPub in key or AKPKpPriv in key)
    check2 = key[KpAlg] in {MlDsa44, MlDsa65, MlDsa87}

    return check2 and check1


@pytest.mark.parametrize('kty_attr, kty_value',
                         [(KpKty, KtyAKP), ('KTY', 'AKP'), (1, 7),
                          (KpKty, 'AKP'), (KpKty, 7),
                          ('KTY', KtyAKP), ('KTY', 7),
                          (1, KtyAKP), (1, 'AKP')])
@pytest.mark.parametrize('alg_attr, alg_value', [(KpAlg, MlDsa87), ('ALG', MlDsa87), (3, MlDsa87)])
@pytest.mark.parametrize('pub_attr, pub_value', [(AKPKpPub, os.urandom(32)), ('PUB', os.urandom(32)), (-1, os.urandom(32))])
@pytest.mark.parametrize('priv_attr, priv_value', [(AKPKpPriv, os.urandom(32)), ('PRIV', os.urandom(32)), (-2, os.urandom(32))])
def test_akp_keys_from_dicts(kty_attr, kty_value, alg_attr, alg_value, pub_attr, pub_value, priv_attr, priv_value):
    # The public and private values used in this test do not form a valid elliptic curve key,
    # but we don't care about that here

    d = {kty_attr: kty_value, alg_attr: alg_value, pub_attr: pub_value, priv_attr: priv_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_akp_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyAKP), ('KTY', 'AKP'), (1, 7)])
@pytest.mark.parametrize('alg_attr, alg_value', [(KpAlg, MlDsa87)])
@pytest.mark.parametrize('priv_attr, priv_value', [(AKPKpPriv, os.urandom(32)), ('PRIV', os.urandom(32)), (-2, os.urandom(32))])
def test_akp_private_key_from_dicts(kty_attr, kty_value, alg_attr, alg_value, priv_attr, priv_value):
    # The public and private values used in this test do not form a valid ML key,
    # but we don't care about that here

    d = {kty_attr: kty_value, alg_attr: alg_value, priv_attr: priv_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_akp_key(cose_key)


@pytest.mark.parametrize('kty_attr, kty_value', [(KpKty, KtyAKP), ('KTY', 'AKP'), (1, 7)])
@pytest.mark.parametrize('alg_attr, alg_value', [(KpAlg, MlDsa87), ('ALG', MlDsa87), (3, MlDsa87)])
@pytest.mark.parametrize('pub_attr, pub_value', [(AKPKpPub, os.urandom(32)), ('PUB', os.urandom(32)), (-1, os.urandom(32))])
def test_akp_public_keys_from_dicts(kty_attr, kty_value, alg_attr, alg_value, pub_attr, pub_value):
    # The public and private values used in this test do not form a valid ML key,
    # but we don't care about that here

    d = {kty_attr: kty_value, alg_attr: alg_value, pub_attr: pub_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_akp_key(cose_key)


@pytest.mark.parametrize('key_class', [mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey])
@pytest.mark.xfail(
    sys.version_info < (3, 9),
    reason="Feature not supported in older cryptography versions"
)
def test_akp_private_key_from_pem(key_class):
    private_key = key_class.generate()
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    cose_key = CoseKey.from_pem_private_key(pem)
    assert _is_valid_akp_key(cose_key)


@pytest.mark.parametrize('key_class', [mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey])
@pytest.mark.xfail(
    sys.version_info < (3, 9),
    reason="Feature not supported in older cryptography versions"
)
def test_akp_public_key_from_pem(key_class):
    private_key = key_class.generate()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    cose_key = CoseKey.from_pem_public_key(pem)
    assert _is_valid_akp_key(cose_key)


@pytest.mark.parametrize('alg', [MlDsa44, MlDsa65, MlDsa87, 'MLDSA87', -50])
@pytest.mark.xfail(
    sys.version_info < (3, 9),
    reason="Feature not supported in older cryptography versions"
)
def test_akp_key_generation_encoding_decoding(alg):
    trials = 256

    for _ix in range(trials):
        akp_test = AKPKey.generate_key(alg=alg)
        akp_encoded = akp_test.encode()
        akp_decoded = CoseKey.decode(akp_encoded)
        assert _is_valid_akp_key(akp_decoded)


@pytest.mark.parametrize('alg', [MlDsa44, MlDsa65, MlDsa87, 'MLDSA87', -50])
@pytest.mark.xfail(
    sys.version_info < (3, 9),
    reason="Feature not supported in older cryptography versions"
)
def test_akp_key_generation(alg):
    key = AKPKey.generate_key(alg)

    assert _is_valid_akp_key(key)


@pytest.mark.parametrize('alg', [MlDsa44, MlDsa65, MlDsa87])
def test_akp_key_construction(alg):
    key = AKPKey(alg=alg, pub=os.urandom(32), priv=os.urandom(32), optional_params={})

    assert _is_valid_akp_key(key)

    serialized = key.encode()
    _ = CoseKey.decode(serialized)


@pytest.mark.parametrize('alg', [MlDsa44, MlDsa65, MlDsa87])
def test_fail_on_missing_key_values(alg):
    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = AKPKey(alg=alg)

    assert "Either the public values or the private value must be specified" in str(excinfo.value)


def test_fail_on_missing_alg_attr():
    cose_key = {KpKty: KtyAKP, AKPKpPub: os.urandom(32), AKPKpPriv: os.urandom(32)}

    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = CoseKey.from_dict(cose_key)

    assert "COSE curve cannot be None" in str(excinfo.value)


@pytest.mark.parametrize('alg', [MlDsa44, MlDsa65, MlDsa87])
@pytest.mark.parametrize('kty', [KtyEC2, KtySymmetric, 2, 4])
def test_fail_on_illegal_kty(alg, kty):
    params = {KpKty: kty}

    with pytest.raises(CoseIllegalKeyType) as excinfo:
        _ = AKPKey(alg=alg, pub=os.urandom(32), priv=os.urandom(32), optional_params=params)

    assert "Illegal key type in AKP COSE Key" in str(excinfo.value)


def test_remove_empty_keyops_list():
    cose_key = {KpKty: KtyAKP, AKPKpPriv: os.urandom(32), KpAlg: MlDsa87, KpKeyOps: []}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps not in key


def test_existing_non_empty_keyops_list():
    cose_key = {KpKty: KtyAKP, AKPKpPriv: os.urandom(32), KpAlg: MlDsa87, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps in key


@pytest.mark.xfail(
    sys.version_info < (3, 9),
    reason="Feature not supported in older cryptography versions"
)
def test_key_ops_setter_getter():
    key = AKPKey.generate_key('MLDSA87')
    key.key_ops = [SignOp]

    assert SignOp in key.key_ops

    with pytest.raises(CoseIllegalKeyOps) as excinfo:
        key.key_ops = [MacVerifyOp]

    assert "Invalid COSE key operation" in str(excinfo)


def test_dict_operations_on_akp_key():
    cose_key = {KpKty: KtyAKP, AKPKpPriv: os.urandom(32), KpAlg: MlDsa87, KpKeyOps: [SignOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKty in key
    assert AKPKpPriv in key
    assert AKPKpPub not in key
    assert 1 in key
    assert -2 in key
    assert -1 not in key
    assert KpAlg in key
    assert 'ALG' in key


def test_key_set_alg():
    # Key from https://www.rfc-editor.org/rfc/rfc9964.html#appendix-A.2
    key = 'a5025820b8969ab4b37da9f0684e42647eb8a0be8b5b661ebf5d76f0583bf5b8d3a8059a010703382f20590520ba71f9f64e11baeb58fa9c6fbb6e14e61f18643dab495b47539a9166ca0198131c44f826bbd56e34e55db5e5e2d733485e39ea260fc6000c5ea4ba80d3455cde53b46f34482aedfd5450fc2e1ba4f25d15f9c144242fb39bb52287189030c50498e1717b7c758b190a6748ea9aa3f7acaaf2c7cb526ed717c9f79aeb84214fa5cd8ded92a0c3fa1558810f12c7050a367708d196cd24e5af974904aed8e4ce8872e8696b0b7bca50e452cd7d30ea9a4adac0311d672c6bde8496240b07431463708895cd9bafc31632d7397649388fdafcbf7d305a3de9a495eca7433a8f83ba0f0b25c413c6e39c96eb7d691b34d37ce37f1eead1cf217e25ef34eecf3f7c60f84b8edfdde8405d4f832576c61ef98e0a2f28da187700953924f686b94614705bcf53d33fedd4348edddbdf28b5065e1f20775043e85cf931f829179363a1a7e7404a838ec00086b0976386fe637c98244757e3f769ddd4467471bfad670f9a05f8246ee50a7b1eaf87fc4069c3ae2aa2033258117792f0bcd49e083fd1bc7496abff29cc94e4868b21214ed316525399a610fbdd4a80e7c80715f29578e2a84bb40bdddbd9f47a11b6e7da118a1b658d359e8aef55eb46b5376b5b655979984a922beebfc59bcd600d5309dccd72dbf0787db8ba757b537c1eafd5c0f50ea4bc9583549e2829a42c28cac248c96d78124c47159b18aedd754aba17b19d430fb78f633ea9d26f54a9bd50f8d8f6b73594f828976e7ea09c53bbb9f11a56c9507fb89b9a5ebc037a37267a95f85b8d64ca97192b10a66f417b3f61fe9ca57130a48fd925eae2ab5502d571c8a51903c1d398f4c1f76a7e11743976afdbc697f23094a3cd761ff9685de32e09fb3c28add453490300bc7c89dc01780096071722945775f264e1b0623bcf4619c712c838761205d87691b75ef360196cbb9e9b92a0d4c4ed62326e5024d77510b8ee2c7426cc22eae209dc9f13bde6bf08f5e7181bd3b459450b451a51539a715c21d67dd330eb5970db00d9edbfb2822b036fa13bafeb86d8dc78866e3f8d43e53d78cca5595a6faf886b5dc112f1cf4adcfa875800d90b48883af97316fe1506873fc157e570eacbfd222868d14234101966afb6bf9940829253a953ada89fc756b6a849f70acb9838e69faa50bba75e3e89c2adb57e86d088ab9b04a28e670709172243ec5e0008a5ceaf3f8722f487302596ffd755ad1b82a49c34b3469515b46aa290cd86ee38ea7a9be3f103610335b531cca333ddfe32b14510f4b07ef95fc6684e8c454a92c10dbb5d59c7a7c63fb305fe881967d99e669eb632840582560bb403431d40f75a4954908482278292821f4ea91e42e78fa48caee3c836146dcfd738d117e92e9a15137d28e8e6a4b4622650cb413504cb3a335d44beec5746c1c294b1e8cb99cb608d928f8ce3563632c521f23d13c61a8f61c01df8c96c7360db4f3c68aa5d2fdd342a62ff3459c116389421ab43e8584c45882b50e6e4e96db6f0b8fde890d5dbfadcd88690b449e64240ddb2023747f308363e301aa77757169fc6150628d5920b5aa1ab1c8cbf44cb00e025d7879d72b479e3af5311c785725590da9c89b9fc3b8450769554eb44d203eba2bbaef9cad2237011c2ea44eff00f299a48ffe28ca93ddf85f76608242ef8d6cc24610a1e2078fcac4f9385c314905ecaa82e553916d94d1a7c1ec652aa08897083daa2ebb1775fbc471ae27777d7904ea9f1b92bcac3d8a3158426087b645b1108f0d65fec93789c053743ca14fd63d05e98b652df2b9c2ff9ce05f1940703ffb273f80e0e2732eca9960d981b4cfd3b7bb8045b3c3830546b9dd8db0d2158200000000000000000000000000000000000000000000000000000000000000000'
    key = CoseKey.decode(unhexlify(key))

    assert key.alg == MlDsa44

    key.alg = MlDsa87

    assert key.alg == MlDsa87

    key.alg = MlDsa65.identifier

    assert key.alg == MlDsa65


@pytest.mark.xfail(
    sys.version_info < (3, 9),
    reason="Feature not supported in older cryptography versions"
)
def test_key_generation_with_optional_parameters():
    key = AKPKey.generate_key(alg='MLDSA87', optional_params={'KpKid': 4})
    assert key is not None
