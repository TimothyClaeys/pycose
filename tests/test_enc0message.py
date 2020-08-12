import os
from binascii import unhexlify, hexlify

from pytest import mark, fixture, skip

from pycose import CoseMessage
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.cosekey import SymmetricKey, CoseKey, KeyOps
from pycose.enc0message import Enc0Message
from tests.conftest import generic_test_setup, create_cose_key, extract_protected_header, extract_unprotected_header


@fixture
def setup_encrypt0_tests(encrypt0_test_input: dict) -> tuple:
    return generic_test_setup(encrypt0_test_input)


@mark.encoding
def test_encrypt0_encoding(setup_encrypt0_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt0_tests

    # initialize a COSE_Encrypt0 message
    enc0 = Enc0Message(
        phdr=extract_protected_header(test_input, 'encrypted'),
        uhdr=extract_unprotected_header(test_input, 'encrypted'),
        payload=test_input['plaintext'].encode('utf-8'),
        external_aad=unhexlify(test_input['encrypted'].get("external", b''))
    )

    # verify internal _enc_structure
    assert enc0._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # set up key data and verify CEK
    enc0.key = create_cose_key(SymmetricKey, test_input["encrypted"]["recipients"][0]["key"], usage=KeyOps.ENCRYPT)
    assert enc0.key_bytes == unhexlify(test_intermediate['CEK_hex'])

    # verify encoding (with automatic encryption)
    if fail:
        assert enc0.encode(encrypt=True) != unhexlify(test_output)
    else:
        assert enc0.encode(encrypt=True) == unhexlify(test_output)


@mark.decoding
def test_encrypt0_decoding(setup_encrypt0_tests: tuple) -> None:
    title, test_input, test_output, test_intermediate, fail = setup_encrypt0_tests

    if fail:
        skip("invalid test input")

    # parse initial message
    cose_msg = CoseMessage.decode(unhexlify(test_output))

    # verify parsed (un)protected header
    assert cose_msg.phdr == extract_protected_header(test_input, 'encrypted')
    assert cose_msg.uhdr == extract_unprotected_header(test_input, 'encrypted')

    # prepare and verify pre-shared key
    key = create_cose_key(SymmetricKey, test_input["encrypted"]["recipients"][0]["key"], usage=KeyOps.ENCRYPT)
    cose_msg.key = key
    assert cose_msg.key_bytes == unhexlify(test_intermediate['CEK_hex'])

    # look for external data and verify internal enc_structure
    cose_msg.external_aad = unhexlify(test_input['encrypted'].get('external', b''))
    assert cose_msg._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # (1) verify decryption
    nonce = unhexlify(test_input['rng_stream'][0].encode('utf-8'))
    assert cose_msg.decrypt(nonce=nonce, key=key) == test_input['plaintext'].encode('utf-8')

    # (2) verify decryption
    assert cose_msg.decrypt(key=key) == test_input['plaintext'].encode('utf-8')

    # (3) verify decryption
    cose_msg.key = key
    assert cose_msg.decrypt() == test_input['plaintext'].encode('utf-8')

    # re-encode and verify we are back where we started
    assert cose_msg.encode(encrypt=False) == unhexlify(test_output)


@mark.parametrize("phdr, uhdr, payload, key",
                  [
                      ({CoseHeaderParam.ALG: CoseAlgorithm.A128GCM},
                       {CoseHeaderParam.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       b'',
                       SymmetricKey(kid=b'you_know', k=os.urandom(16))),
                      ({CoseHeaderParam.ALG: CoseAlgorithm.A192GCM},
                       {CoseHeaderParam.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       os.urandom(50),
                       SymmetricKey(kid=b'you_know', k=os.urandom(16))),
                      ({CoseHeaderParam.ALG: CoseAlgorithm.A256GCM},
                       {CoseHeaderParam.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       os.urandom(100),
                       SymmetricKey(kid=b'you_know', k=os.urandom(16)))
                  ], ids=['test_encode_decode_1', 'test_encode_decode_2', 'test_encode_decode_3'])
def test_encode_decode_encrypt0(phdr, uhdr, payload, key):
    # create and encode a message
    original = Enc0Message(phdr, uhdr, payload)
    original.key = key
    encoded = original.encode()

    # decode the message
    decoded = CoseMessage.decode(encoded)

    # verify the different parts
    assert type(decoded) == Enc0Message
    assert original.encrypt() == decoded.payload
    assert decoded.phdr == phdr
    assert decoded.uhdr == uhdr

    # set the key and decode the message
    decoded.key = key
    assert decoded.decrypt() == payload


@mark.parametrize("phdr, uhdr, alg, key1, key2, nonce, expected",
                  [
                      ({CoseHeaderParam.ALG: CoseAlgorithm.AES_CCM_16_64_128},
                       {CoseHeaderParam.IV: unhexlify(b'89F52F65A1C580933B5261A72F')},
                       None,
                       SymmetricKey(
                           kid=b'our-secret',
                           key_ops=KeyOps.ENCRYPT,
                           k=CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbg")),
                       None,
                       None,
                       b'6899DA0A132BD2D2B9B10915743EE1F7B92A4680E7C51BDBC1B320EA',),
                      ({CoseHeaderParam.ALG: CoseAlgorithm.AES_CCM_16_64_128},
                       {},
                       None,
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
    m.key = key1
    m.payload = m.encrypt(alg, nonce, key2)

    key = key1 if key1 is not None else key2

    assert m._enc_structure == unhexlify(b"8368456E63727970743043A1010A40")
    assert key.key_bytes == unhexlify(b"849B57219DAE48DE646D07DBB533566E")
    assert hexlify(m.payload).upper() == expected
