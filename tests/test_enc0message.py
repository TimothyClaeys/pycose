import os
from binascii import unhexlify

import pytest

from pycose import CoseMessage
from pycose.attributes import CoseHeaderParam
from pycose.enc0message import Enc0Message
from tests.conftest import aes_ccm_examples, aes_gcm_examples, encrypted_tests


@pytest.mark.encoding
@pytest.mark.parametrize('encrypt0_test_cases',
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

    m.key = unhexlify(encrypt0_test_cases['intermediates']['CEK_hex'])

    assert m._enc_structure == unhexlify(encrypt0_test_cases['intermediates']['AAD_hex'])

    m.encrypt()

    if fail:
        assert m.encode() != unhexlify(encrypt0_test_cases["output"]["cbor"])
    else:
        assert m.encode() == unhexlify(encrypt0_test_cases["output"]["cbor"])


@pytest.mark.decoding
@pytest.mark.parametrize('encrypt0_test_cases',
                         [os.path.join(aes_ccm_examples, v) for v in os.listdir(aes_ccm_examples)],
                         indirect=['encrypt0_test_cases'])
def test_encrypt_decoding(encrypt0_test_cases: dict) -> None:
    try:
        output_data = encrypt0_test_cases['output']
        input_data = encrypt0_test_cases['input']
    except (TypeError, KeyError):
        pytest.skip("Invalid parameters")
        return

    msg = CoseMessage.decode(unhexlify(output_data['cbor']))
