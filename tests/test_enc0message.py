import os
from binascii import hexlify, unhexlify

from pytest import mark, fixture, skip

from pycose import CoseMessage
from pycose.algorithms import CoseAlgorithms
from pycose.cosebase import HeaderKeys
from pycose.enc0message import Enc0Message
from pycose.keys.cosekey import KeyOps, CoseKey
from pycose.keys.symmetric import SymmetricKey
from tests.conftest import generic_test_setup, extract_phdr, extract_uhdr, extract_alg, extract_nonce, create_cose_key


@fixture
def setup_encrypt0_tests(encrypt0_test_input: dict) -> tuple:
    return generic_test_setup(encrypt0_test_input)


@mark.encoding
def test_encrypt0_encoding(setup_encrypt0_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt0_tests
    alg = extract_alg(test_input['encrypted'])
    nonce = extract_nonce(test_input, 0)

    # initialize a COSE_Encrypt0 message
    enc0 = Enc0Message(
        phdr=extract_phdr(test_input, 'encrypted'),
        uhdr=extract_uhdr(test_input, 'encrypted'),
        payload=test_input['plaintext'].encode('utf-8'),
        external_aad=unhexlify(test_input['encrypted'].get("external", b'')))

    # set up key data and verify CEK
    key = create_cose_key(SymmetricKey, test_input["encrypted"]["recipients"][0]["key"])

    # verify internal _enc_structure
    assert enc0._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # verify encoding (with automatic encryption)
    if fail:
        assert enc0.encode(alg=alg, nonce=nonce, key=key) != unhexlify(test_output)
    else:
        assert enc0.encode(alg=alg, nonce=nonce, key=key) == unhexlify(test_output)


@mark.decoding
def test_encrypt0_decoding(setup_encrypt0_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt0_tests
    alg = extract_alg(test_input['encrypted'])
    nonce = extract_nonce(test_input, 0)

    if fail:
        skip("invalid test input")

    # parse initial message
    msg: Enc0Message = CoseMessage.decode(unhexlify(test_output))

    # verify parsed (un)protected header
    assert msg.phdr == extract_phdr(test_input, 'encrypted')
    assert msg.uhdr == extract_uhdr(test_input, 'encrypted')

    # prepare and verify pre-shared key
    key = create_cose_key(
        SymmetricKey,
        test_input["encrypted"]["recipients"][0]["key"],
        alg=alg,
        usage=KeyOps.DECRYPT)

    msg.key = key
    assert msg.key.k == unhexlify(test_intermediate['CEK_hex'])

    # look for external data and verify internal enc_structure
    msg.external_aad = unhexlify(test_input['encrypted'].get('external', b''))
    assert msg._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # verify decryption
    assert msg.decrypt(nonce=nonce, key=key) == test_input['plaintext'].encode('utf-8')

    # re-encode and verify we are back where we started
    assert msg.encode(encrypt=False, key=key, nonce=nonce) == unhexlify(test_output)


@mark.parametrize("phdr, uhdr, payload, key",
                  [
                      ({HeaderKeys.ALG: CoseAlgorithms.A128GCM},
                       {HeaderKeys.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       b'',
                       SymmetricKey(kid=b'you_know', k=os.urandom(16), alg=CoseAlgorithms.A128GCM)),
                      ({HeaderKeys.ALG: CoseAlgorithms.A192GCM},
                       {HeaderKeys.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       os.urandom(50),
                       SymmetricKey(kid=b'you_know', k=os.urandom(16), alg=CoseAlgorithms.A192GCM)),
                      ({HeaderKeys.ALG: CoseAlgorithms.A256GCM},
                       {HeaderKeys.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       os.urandom(100),
                       SymmetricKey(kid=b'you_know', k=os.urandom(16), alg=CoseAlgorithms.A256GCM))
                  ], ids=['test_encode_decode_1', 'test_encode_decode_2', 'test_encode_decode_3'])
def test_encode_decode_encrypt0(phdr, uhdr, payload, key):
    # create and encode a message
    original: Enc0Message = Enc0Message(phdr, uhdr, payload)
    encoded = original.encode(key=key, nonce=original.uhdr[HeaderKeys.IV])

    # decode the message
    decoded: Enc0Message = CoseMessage.decode(encoded)

    # verify the different parts
    assert type(decoded) == Enc0Message
    assert original.encrypt(key=key, nonce=original.uhdr[HeaderKeys.IV]) == decoded.payload
    assert decoded.phdr == phdr
    assert decoded.uhdr == uhdr

    # set the key and decode the message
    key.key_ops = KeyOps.DECRYPT
    assert decoded.decrypt(key=key, nonce=original.uhdr[HeaderKeys.IV]) == payload


@mark.parametrize("phdr, uhdr, alg, key1, key2, nonce, expected",
                  [
                      ({HeaderKeys.ALG: CoseAlgorithms.AES_CCM_16_64_128},
                       {HeaderKeys.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       None,
                       SymmetricKey(
                           kid=b'our-secret',
                           alg=CoseAlgorithms.AES_CCM_16_64_128,
                           key_ops=KeyOps.ENCRYPT,
                           k=CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbg")),
                       None,
                       unhexlify("89F52F65A1C580933B5261A72F"),
                       b'6899DA0A132BD2D2B9B10915743EE1F7B92A4680E7C51BDBC1B320EA',),
                      ({HeaderKeys.ALG: CoseAlgorithms.AES_CCM_16_64_128},
                       {},
                       CoseAlgorithms.AES_CCM_16_64_128,
                       SymmetricKey(
                           kid=b'our-secret',
                           key_ops=KeyOps.ENCRYPT,
                           k=CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbg")),
                       None,
                       unhexlify(b'89F52F65A1C580933B5261A72F'),
                       b'6899DA0A132BD2D2B9B10915743EE1F7B92A4680E7C51BDBC1B320EA',),
                  ], ids=['standalone_encryption_1', 'standalone_encryption_2']
                  )
def test_encrypt0_standalone_encryption(phdr, uhdr, alg, key1, key2, nonce, expected):
    m = Enc0Message(phdr, uhdr, b'This is the content.')
    m.payload = m.encrypt(nonce=nonce, key=key1, alg=alg)

    key = key1 if key1 is not None else key2

    assert m._enc_structure == unhexlify(b"8368456E63727970743043A1010A40")
    assert key.k == unhexlify(b"849B57219DAE48DE646D07DBB533566E")
    assert hexlify(m.payload).upper() == expected
