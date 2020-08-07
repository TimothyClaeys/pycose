import os
from binascii import unhexlify

import pytest

from pycose import EncMessage
from pycose.attributes import CoseHeaderParam
from pycose.cosekey import SymmetricKey
from pycose.recipient import CoseRecipient
from tests.conftest import aes_ccm_examples, aes_gcm_examples, encrypted_tests

test_cases = [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples)]


@pytest.mark.encoding
@pytest.mark.parametrize('encrypt_test_cases', test_cases, indirect=['encrypt_test_cases'])
def test_encrypt_encoding(encrypt_test_cases: dict) -> None:
    try:
        input_data = encrypt_test_cases['input']
    except (TypeError, KeyError):
        pytest.skip("Invalid parameters")
        return

    if 'fail' in encrypt_test_cases or "failures" in encrypt_test_cases:
        fail = True
    else:
        fail = False

    m = EncMessage(payload=input_data['plaintext'].encode('utf-8'))
    m.phdr = input_data.get('enveloped').get('protected', {})
    m.uhdr = input_data.get('enveloped').get('unprotected', {})

    nonce = None
    if 'rng_stream' in input_data:
        m.uhdr_update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][0])})
    else:
        if 'unsent' in input_data['enveloped']:
            nonce = unhexlify(input_data.get('enveloped').get('unsent').get('IV_hex'))

    # check for external data and verify internal _enc_structure
    m.external_aad = unhexlify(input_data.get('enveloped').get('external', b''))
    assert m._enc_structure == unhexlify(encrypt_test_cases['intermediates']['AAD_hex'])

    # set up the CEK.
    m.key = SymmetricKey(k=unhexlify(encrypt_test_cases['intermediates']['CEK_hex']))

    # create the recipients
    recipients = []
    recipients_data = input_data.get("enveloped").get("recipients")
    for r_info in recipients_data:
        phdr = r_info.get('protected', {})
        uhdr = r_info.get('unprotected', {})
        if r_info.get('recipients', []):
            raise NotImplementedError("Cannot deal with this right now.")

        rcpt = CoseRecipient(phdr=phdr, uhdr=uhdr, payload=m.key.key_bytes, recipients=[])
        rcpt.key = SymmetricKey(k=r_info['key']['k'], kid=r_info["key"]["kid"])
        recipients.append(rcpt.encode())

    m.recipients = recipients

    # verify encoding (with automatic encryption)
    if fail:
        assert m.encode(encrypt=True, nonce=nonce) != unhexlify(encrypt_test_cases["output"]["cbor"])
    else:
        assert m.encode(encrypt=True, nonce=nonce) == unhexlify(encrypt_test_cases["output"]["cbor"])
