from binascii import unhexlify, hexlify

from pycose.keys.curves import Ed25519
from pycose.messages import Enc0Message, Sign1Message, Mac0Message
from pycose.keys import CoseKey
from pycose.algorithms import A128GCM, EdDSA, HMAC256
from pycose.headers import Algorithm, KID, IV
from pycose.keys.keyparam import KpKty, SymKpK, KpKeyOps, OKPKpCurve, OKPKpD, OKPKpX
from pycose.keys.keytype import KtySymmetric, KtyOKP
from pycose.keys.keyops import EncryptOp, DecryptOp, SignOp, VerifyOp, MacCreateOp, MacVerifyOp


def test_simple_enc0message():
    msg = Enc0Message(
        phdr={Algorithm: A128GCM, IV: b'000102030405060708090a0b0c'},
        uhdr={KID: b'kid1'},
        payload='some secret message'.encode('utf-8'))

    assert str(msg) == "<COSE_Encrypt0: [{'Algorithm': 'A128GCM', 'IV': \"b'00010' ... (26 B)\"}, {'KID': b'kid1'}, " \
                       "b'some ' ... (19 B)]>"

    cose_key = {
        KpKty: KtySymmetric,
        SymKpK: unhexlify(b'000102030405060708090a0b0c0d0e0f'),
        KpKeyOps: [EncryptOp, DecryptOp]}

    cose_key = CoseKey.from_dict(cose_key)
    assert str(cose_key) == "<COSE_Key(Symmetric): {'SymKpK': \"b'\\\\x00\\\\x01\\\\x02\\\\x03\\\\x04' ... (16 B)\", " \
                            "'KpKty': 'KtySymmetric', 'KpKeyOps': ['EncryptOp', 'DecryptOp']}>"

    msg.key = cose_key

    # the encode() function performs the encryption automatically
    encoded = msg.encode()
    assert hexlify(encoded) == b'd0835820a2010105581a3030303130323033303430353036303730383039306130623063a104446b696' \
                               b'4315823cca3441a2464d240e09fe9ee0ea42a7852a4f41d9945325c1f8d3b1353b8eb83e6a62f'

    # decode and decrypt
    decoded = Enc0Message.decode(encoded)

    decoded.key = cose_key
    assert hexlify(decoded.payload) == b'cca3441a2464d240e09fe9ee0ea42a7852a4f41d9945325c1f8d3b1353b8eb83e6a62f'

    assert decoded.decrypt() == b'some secret message'


def test_symmetric_key_example2():
    simple_dict = {
        'KTY': KtySymmetric,
        'ALG': A128GCM,
        'K': unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    cose_key = CoseKey.from_dict(simple_dict)

    # encode/serialize key
    serialized_key = cose_key.encode()
    assert str(serialized_key) == \
           str(b'\xa3\x01\x04\x03\x01 P\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f')

    assert str(CoseKey.decode(serialized_key)) == "<COSE_Key(Symmetric): " \
                                                  "{'SymKpK': \"b'\\\\x00\\\\x01\\\\x02\\\\x03\\\\x04' ... (16 B)\", " \
                                                  "'KpKty': 'KtySymmetric', 'KpAlg': 'A128GCM'}>"


def test_simple_sign1message():
    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: b'kid2'},
        payload='signed message'.encode('utf-8')
    )

    assert str(msg) == "<COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'' ... (0 B)]>"

    cose_key = {
        KpKty: KtyOKP,
        OKPKpCurve: Ed25519,
        KpKeyOps: [SignOp, VerifyOp],
        OKPKpD: unhexlify(b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
        OKPKpX: unhexlify(b'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')}

    cose_key = CoseKey.from_dict(cose_key)
    assert str(cose_key) == "<COSE_Key(OKPKey): {'OKPKpD': \"b'\\\\x9da\\\\xb1\\\\x9d\\\\xef' ... (32 B)\"," \
                            " 'OKPKpX': \"b'\\\\xd7Z\\\\x98\\\\x01\\\\x82' ... (32 B)\"," \
                            " 'OKPKpCurve': 'Ed25519', 'KpKty': 'KtyOKP', 'KpKeyOps': ['SignOp', 'VerifyOp']}>"

    msg.key = cose_key
    encoded = msg.encode()
    assert hexlify(encoded) == b'd28449a2012704446b696432a04e7369676e6564206d6573736167655840cc87665ffd3' \
                               b'fa33d96f3b606fcedeaef839423221872d0bfa196e069a189a607c2284924c3abb80e94' \
                               b'2466cd300cc5d18fe4e5ea1f3ebdb62ef8419109447d03'

    decoded = Sign1Message.decode(encoded)
    assert str(decoded) == "<COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), " \
                           "b'\\xcc\\x87f_\\xfd' ... (64 B)]>"

    decoded.key = cose_key
    assert decoded.verify_signature()
    assert decoded.payload == b'signed message'


def test_simple_mac0message():
    msg = Mac0Message(
        phdr={Algorithm: HMAC256},
        uhdr={KID: b'kid3'},
        payload='authenticated message'.encode('utf-8'))

    assert str(msg) == "<COSE_Mac0: [{'Algorithm': 'HMAC256'}, {'KID': b'kid3'}, b'authe' ... (21 B), b'' ... (0 B)]>"

    cose_key = {
        KpKty: KtySymmetric,
        SymKpK: unhexlify(b'000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f'),
        KpKeyOps: [MacCreateOp, MacVerifyOp]}

    cose_key = CoseKey.from_dict(cose_key)
    assert str(cose_key) == "<COSE_Key(Symmetric): {'SymKpK': \"b'\\\\x00\\\\x01\\\\x02\\\\x03\\\\x04' ... (32 B)\", " \
                            "'KpKty': 'KtySymmetric', 'KpKeyOps': ['MacCreateOp', 'MacVerifyOp']}>"

    msg.key = cose_key
    # the encode() function automatically computes the authentication tag
    encoded = msg.encode()
    assert hexlify(encoded) == b'd18443a10105a104446b6964335561757468656e74696361746564206d657373616765582019f' \
                               b'6c7d8ddfeaceea6ba4f1cafb563cbf3be157653e29f3258b2957cf23f4e17'

    # decode and authenticate tag
    decoded = Mac0Message.decode(encoded)
    assert str(decoded) == "<COSE_Mac0: [{'Algorithm': 'HMAC256'}, {'KID': b'kid3'}, b'authe' ... (21 B), " \
                           "b'\\x19\\xf6\\xc7\\xd8\\xdd' ... (32 B)]>"

    decoded.key = cose_key
    assert hexlify(decoded.payload) == b'61757468656e74696361746564206d657373616765'

    assert hexlify(decoded.auth_tag) == b'19f6c7d8ddfeaceea6ba4f1cafb563cbf3be157653e29f3258b2957cf23f4e17'

    assert decoded.verify_tag()
