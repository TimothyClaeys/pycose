import os
from binascii import unhexlify

import pytest

from pycose import EncMessage
from tests.conftest import aes_ccm_examples, aes_gcm_examples, encrypted_tests


@pytest.mark.encoding
@pytest.mark.parametrize('encrypt_test_cases',
                         [os.path.join(aes_ccm_examples, v) for v in os.listdir(aes_ccm_examples)] +
                         [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples)] +
                         [os.path.join(encrypted_tests, v) for v in os.listdir(encrypted_tests)],
                         indirect=['encrypt_test_cases'])
def test_encrypt_encoding(encrypt_test_cases: dict) -> None:
    pass
    # try:
    #     case = encrypt_test_cases['input']
    # except (TypeError, KeyError):
    #     pytest.skip("Invalid parameters")
    #     return

    # if 'fail' in encrypt_test_cases or "failures" in case:
    #     fail = True
    # else:
    #     fail = False

    # m = EncMessage(payload=case['plaintext'].encode('utf-8'))

    # m.phdr = case.get('enveloped').get('protected')
    # m.uhdr = case.get('enveloped').get('unprotected')

    # if 'rng_stream' in case:
    #     m.uhdr_update({'IV': unhexlify(case['rng_stream'][0])})

    # if 'external' in case['enveloped']:
    #     m.external_aad = unhexlify(case['enveloped']['external'])

    # m.key = unhexlify(encrypt_test_cases['intermediates']['CEK_hex'])

    # assert m._enc_structure == unhexlify(encrypt_test_cases['intermediates']['AAD_hex'])
