import os
from binascii import unhexlify, hexlify

import pytest
from pytest import mark

from pycose import CoseMessage
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.cosekey import SymmetricKey, CoseKey, KeyOps
from pycose.enc0message import Enc0Message
from tests.conftest import aes_ccm_examples, aes_gcm_examples, encrypted_tests

test_cases = [os.path.join(aes_ccm_examples, v) for v in os.listdir(aes_ccm_examples) if '-enc-' in v] + \
             [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples) if '-enc-' in v] + \
             [os.path.join(encrypted_tests, v) for v in os.listdir(encrypted_tests)]


@mark.encoding
@mark.parametrize('encrypt0_test_cases', test_cases, indirect=['encrypt0_test_cases'])
def test_encrypt0_encoding(encrypt0_test_cases: dict) -> None:
    try:
        input_data = encrypt0_test_cases['input']
    except (TypeError, KeyError):
        return pytest.skip("Invalid parameters")

    if 'fail' in encrypt0_test_cases or "failures" in input_data:
        fail = True
    else:
        fail = False

    # create message and set headers
    m = Enc0Message(payload=input_data['plaintext'].encode('utf-8'))
    m.phdr = input_data.get('encrypted').get('protected', {})
    m.uhdr = input_data.get('encrypted').get('unprotected', {})
    if 'rng_stream' in input_data:
        m.uhdr_update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][0])})

    # check for external data and verify internal _enc_structure
    m.external_aad = unhexlify(input_data.get('encrypted').get('external', b''))
    assert m._enc_structure == unhexlify(encrypt0_test_cases['intermediates']['AAD_hex'])

    # set up key data and verify CEK
    key_data = input_data.get('encrypted').get('recipients')[0].get('key')
    m.key = SymmetricKey(k=CoseKey.base64decode(key_data['k']))
    assert m.key_bytes == unhexlify(encrypt0_test_cases.get('intermediates').get('CEK_hex'))

    # verify encoding (with automatic encryption)
    if fail:
        assert m.encode(encrypt=True) != unhexlify(encrypt0_test_cases["output"]["cbor"])
    else:
        assert m.encode(encrypt=True) == unhexlify(encrypt0_test_cases["output"]["cbor"])


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
                  ]
                  )
def test_encrypt0_standalone_encryption(phdr, uhdr, alg, key1, key2, nonce, expected):
    m = Enc0Message(phdr, uhdr, b'This is the content.')
    m.key = key1
    m.payload = m.encrypt(alg, nonce, key2)

    key = key1 if key1 is not None else key2

    assert m._enc_structure == unhexlify(b"8368456E63727970743043A1010A40")
    assert key.key_bytes == unhexlify(b"849B57219DAE48DE646D07DBB533566E")
    assert hexlify(m.payload).upper() == expected


@mark.decoding
@mark.parametrize('encrypt0_test_cases', test_cases, indirect=['encrypt0_test_cases'])
def test_encrypt0_decoding(encrypt0_test_cases: dict) -> None:
    try:
        output_data = encrypt0_test_cases['output']
        input_data = encrypt0_test_cases['input']
    except (TypeError, KeyError):
        return pytest.skip("Invalid parameters")

    if 'fail' in encrypt0_test_cases or "failures" in input_data:
        pytest.skip("Invalid parameters")

    # parse initial message
    msg = CoseMessage.decode(unhexlify(output_data['cbor']))

    # verify parsed protected header
    assert msg.phdr == input_data.get('encrypted').get('protected', {})

    # verify parsed unprotected header
    unprotected = input_data.get('encrypted').get('unprotected', {})
    unprotected.update({} if input_data.get('rng_stream') is None else {
        CoseHeaderParam.IV: unhexlify(input_data.get('rng_stream')[0].encode('utf-8'))})
    assert msg.uhdr == unprotected

    # prepare and verify pre-shared key
    key = input_data.get('encrypted').get("recipients")[0].get("key")
    key = SymmetricKey(kid=key['kid'], key_ops=KeyOps.DECRYPT, k=CoseKey.base64decode(key["k"]))
    assert key.key_bytes == unhexlify(encrypt0_test_cases.get('intermediates').get('CEK_hex'))

    # look for external data and verify internal enc_structure
    msg.external_aad = unhexlify(input_data.get('encrypted').get('external', b''))
    assert msg._enc_structure == unhexlify(encrypt0_test_cases.get('intermediates').get('AAD_hex'))

    # (1) verify decryption
    nonce = unhexlify(input_data.get('rng_stream')[0].encode('utf-8'))
    assert msg.decrypt(nonce=nonce, key=key) == input_data.get('plaintext', b'').encode('utf-8')

    # (2) verify decryption
    assert msg.decrypt(key=key) == input_data.get('plaintext', b'').encode('utf-8')

    # (3) verify decryption
    msg.key = key
    assert msg.decrypt() == input_data.get('plaintext', b'').encode('utf-8')

    # re-encode and verify we are back where we started
    assert msg.encode(encrypt=False) == unhexlify(output_data['cbor'])


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
                  ])
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
