import os
from binascii import unhexlify, hexlify

import pytest
from pytest import mark

from pycose import CoseMessage
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.cosekey import SymmetricKey, CoseKey, KeyOps
from pycose.enc0message import Enc0Message
from tests.conftest import aes_ccm_examples, aes_gcm_examples, encrypted_tests


@mark.encoding
@mark.parametrize('encrypt0_test_cases',
                  [os.path.join(aes_ccm_examples, v) for v in os.listdir(aes_ccm_examples)] +
                  [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples)] +
                  [os.path.join(encrypted_tests, v) for v in os.listdir(encrypted_tests)],
                  indirect=['encrypt0_test_cases'])
def test_encrypt0_encoding(encrypt0_test_cases: dict) -> None:
    try:
        input_data = encrypt0_test_cases['input']
    except (TypeError, KeyError):
        pytest.skip("Invalid parameters")
        return

    if 'fail' in encrypt0_test_cases or "failures" in input_data:
        fail = True
    else:
        fail = False

    m = Enc0Message(payload=input_data['plaintext'].encode('utf-8'))

    m.phdr = input_data.get('encrypted').get('protected', {})
    m.uhdr = input_data.get('encrypted').get('unprotected', {})

    if 'rng_stream' in input_data:
        m.uhdr_update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][0])})

    m.external_aad = unhexlify(input_data.get('encrypted').get('external', b''))

    key_data = input_data.get('encrypted').get('recipients')[0].get('key')
    m.key = SymmetricKey(k=CoseKey.base64decode(key_data['k']))

    assert m.key_bytes == unhexlify(encrypt0_test_cases.get('intermediates').get('CEK_hex'))
    assert m._enc_structure == unhexlify(encrypt0_test_cases['intermediates']['AAD_hex'])

    if fail:
        assert m.encode() != unhexlify(encrypt0_test_cases["output"]["cbor"])
    else:
        assert m.encode() == unhexlify(encrypt0_test_cases["output"]["cbor"])


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
def test_encrypt0_encryption(phdr, uhdr, alg, key1, key2, nonce, expected):
    m = Enc0Message(phdr, uhdr, b'This is the content.')
    m.key = key1
    m.payload = m.encrypt(alg, nonce, key2)

    key = key1 if key1 is not None else key2

    assert m._enc_structure == unhexlify(b"8368456E63727970743043A1010A40")
    assert key.key_bytes == unhexlify(b"849B57219DAE48DE646D07DBB533566E")
    assert hexlify(m.payload).upper() == expected


@mark.decoding
@mark.parametrize('encrypt0_test_cases',
                  [os.path.join(aes_ccm_examples, v) for v in os.listdir(aes_ccm_examples)],
                  indirect=['encrypt0_test_cases'])
def test_encrypt0_decoding(encrypt0_test_cases: dict) -> None:
    try:
        output_data = encrypt0_test_cases['output']
        input_data = encrypt0_test_cases['input']
    except (TypeError, KeyError):
        pytest.skip("Invalid parameters")
        return

    msg = CoseMessage.decode(unhexlify(output_data['cbor']))
