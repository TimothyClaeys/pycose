from binascii import unhexlify, hexlify

from cose.keys.cosekey import CoseKey
from cose.keys.okp import OKPKey
from cose.keys.rsa import RSAKey
from cose.keys.symmetric import SymmetricKey
from cose.curves import P256, X25519, X448, Ed25519, Ed448, P521, P384
from cose.keys.ec2 import EC2KpCurve, EC2KpY, EC2KpX, EC2Key
from cose.keys.keyparam import KpKty, KpKeyOps
from cose.keys.keytype import KtyEC2, KtyOKP


def test_load_keys():
    key_1 = {
        1: 2,
        -1: 1,
        -2: unhexlify('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
        -3: unhexlify('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB')
    }

    key_2 = {
        'KTY': 2,
        'CURVE': 1,
        'X': unhexlify('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
        'Y': unhexlify('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB')
    }

    key_3 = {
        'KTY': KtyEC2,
        -1: 1,
        'X': unhexlify('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
        'Y': unhexlify('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB')
    }

    key_4 = {
        'KTY': KtyOKP,
        'CURVE': X25519,
        'X': unhexlify('52fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35'),
        'D': unhexlify('c646cddc58126e18105f01ce35056e5ebc35f4d4cc510749a3a5e069c116169a')
    }

    key_5 = {
        'KTY': KtyOKP,
        'CURVE': X25519,
        'X': unhexlify('a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32'),
        'D': unhexlify('bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0')
    }

    wanted = {
        KpKty: KtyEC2,
        EC2KpCurve: P256,
        EC2KpX: unhexlify('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
        EC2KpY: unhexlify('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB'),
        KpKeyOps: []
    }

    assert CoseKey.from_dict(key_1) == wanted
    assert CoseKey.from_dict(key_2) == wanted
    assert CoseKey.from_dict(key_3) == wanted
    assert CoseKey.from_dict(wanted) == wanted

    key_obj = CoseKey.from_dict(key_4)
    cbor_encoding = key_obj.encode()
    # print(hexlify(cbor_encoding))
    assert CoseKey.decode(cbor_encoding) == key_obj

    key_obj = CoseKey.from_dict(key_5)
    cbor_encoding = key_obj.encode()
    print(hexlify(cbor_encoding))
    assert CoseKey.decode(cbor_encoding) == key_obj


def test_encoding_decoding():
    cose_key = CoseKey.from_dict({
        KpKty: KtyEC2,
        EC2KpCurve: P256,
        EC2KpX: unhexlify(b'98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
        EC2KpY: unhexlify(b'F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB'),
        KpKeyOps: []
    })

    cose_key.encode()


def test_ec2key_nist256p_generation():
    trails = 512

    for i in range(trails):
        ec2_test = EC2Key.generate_key(curve=P256)
        ec2_encoded = ec2_test.encode()
        ec2_decoded = CoseKey.decode(ec2_encoded)
        assert ec2_decoded.is_valid_key


def test_ec2key_nist384p_generation():
    trails = 512

    for i in range(trails):
        ec2_test = EC2Key.generate_key(curve=P384)
        ec2_encoded = ec2_test.encode()
        ec2_decoded = CoseKey.decode(ec2_encoded)
        assert ec2_decoded.is_valid_key


def test_ec2key_nist521p_generation():
    trails = 512

    for i in range(trails):
        ec2_test = EC2Key.generate_key(curve=P521)
        ec2_encoded = ec2_test.encode()
        ec2_decoded = CoseKey.decode(ec2_encoded)
        assert ec2_decoded.is_valid_key


def test_okpkey_ed448_generation():
    trails = 512

    for i in range(trails):
        okp_test = OKPKey.generate_key(Ed448)
        okp_encoded = okp_test.encode()
        okp_decoded = CoseKey.decode(okp_encoded)
        assert okp_decoded.is_valid_key


def test_okpkey_x25519_generation():
    trails = 512

    for i in range(trails):
        okp_test = OKPKey.generate_key(X25519)
        okp_encoded = okp_test.encode()
        okp_decoded = CoseKey.decode(okp_encoded)
        assert okp_decoded.is_valid_key


def test_okpkey_ed25519_generation():
    trails = 512

    for i in range(trails):
        okp_test = OKPKey.generate_key(Ed25519)
        okp_encoded = okp_test.encode()
        okp_decoded = CoseKey.decode(okp_encoded)
        assert okp_decoded.is_valid_key


def test_okpkey_x448_generation():
    trails = 512

    for i in range(trails):
        okp_test = OKPKey.generate_key(X448)
        okp_encoded = okp_test.encode()
        okp_decoded = CoseKey.decode(okp_encoded)
        assert okp_decoded.is_valid_key


def test_rsakey_generation():
    trails = 10

    for length in [1024, 2048, 4096]:
        for _i in range(trails):
            sym_test = RSAKey.generate_key(length)
            sym_encoded = sym_test.encode()
            sym_decoded = CoseKey.decode(sym_encoded)
            assert sym_decoded.is_valid_key


def test_symmetrickey_generation():
    trails = 10

    for length in [16, 24, 32]:
        for i in range(trails):
            sym_test = SymmetricKey.generate_key(length)
            sym_encoded = sym_test.encode()
            sym_decoded = CoseKey.decode(sym_encoded)
            assert sym_decoded.is_valid_key
