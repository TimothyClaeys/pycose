import os
from binascii import unhexlify

import pytest

from pycose import EncMessage, CoseMessage
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.cosekey import SymmetricKey, KeyOps, CoseKey
from pycose.recipient import CoseRecipient
from tests.conftest import aes_gcm_examples, enveloped_tests

test_cases = [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples) if '-enc-' not in v] + \
             [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples) if '-enc-' not in v] + \
             [os.path.join(enveloped_tests, v) for v in os.listdir(enveloped_tests)]


@pytest.mark.parametrize('encrypt_test_cases', test_cases, indirect=['encrypt_test_cases'])
def test_encrypt_encoding(encrypt_test_cases: dict) -> None:
    try:
        input_data = encrypt_test_cases['input']
    except (TypeError, KeyError):
        return pytest.skip("Invalid parameters")

    if 'fail' in encrypt_test_cases or "failures" in input_data:
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
        recipients.append(rcpt)

    m.recipients = recipients

    # verify encoding (with automatic encryption)
    output = unhexlify(encrypt_test_cases["output"]["cbor"])
    if fail:
        assert m.encode(encrypt=True, nonce=nonce) != output
    else:
        # (1) test encoding without specifying recipient crypto params
        assert m.encode(encrypt=True, nonce=nonce) == output

        # (2)
        assert m.encode(encrypt=True, nonce=nonce, crypto_params=((True, CoseAlgorithm.DIRECT, None, None),)) == output


@pytest.mark.decoding
@pytest.mark.parametrize('encrypt_test_cases', test_cases, indirect=['encrypt_test_cases'])
def test_encrypt_decoding(encrypt_test_cases: dict) -> None:
    try:
        output_data = encrypt_test_cases['output']
        input_data = encrypt_test_cases['input']
    except (TypeError, KeyError):
        return pytest.skip("Invalid parameters")

    if 'fail' in encrypt_test_cases or "failures" in input_data:
        pytest.skip("Invalid parameters")

    # parse initial message
    msg = CoseMessage.decode(unhexlify(output_data['cbor']))

    # verify parsed protected header
    assert msg.phdr == input_data.get('enveloped').get('protected', {})

    # verify parsed unprotected header
    unprotected = input_data.get('enveloped').get('unprotected', {})

    nonce = None
    if 'rng_stream' in input_data:
        unprotected.update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][0])})
    else:
        if 'unsent' in input_data['enveloped']:
            nonce = unhexlify(input_data.get('enveloped').get('unsent').get('IV_hex'))

    assert msg.uhdr == unprotected

    key = input_data.get('enveloped').get("recipients")[0].get("key")
    key = SymmetricKey(kid=key['kid'], key_ops=KeyOps.DECRYPT, k=CoseKey.base64decode(key["k"]))
    assert key.key_bytes == unhexlify(encrypt_test_cases.get('intermediates').get('CEK_hex'))

    # look for external data and verify internal enc_structure
    msg.external_aad = unhexlify(input_data.get('enveloped').get('external', b''))
    assert msg._enc_structure == unhexlify(encrypt_test_cases.get('intermediates').get('AAD_hex'))

    # verify recipients
    for r1, r2 in zip(msg.recipients, input_data['enveloped']['recipients']):
        assert r1.phdr == r2.get('protected', {})
        assert r1.uhdr == r2.get('unprotected', {})

    # (1) verify decryption
    nonce = nonce if nonce is not None else unhexlify(input_data.get('rng_stream')[0].encode('utf-8'))
    assert msg.decrypt(nonce=nonce, key=key) == input_data.get('plaintext', b'').encode('utf-8')

    # re-encode and verify we are back where we started
    assert msg.encode(encrypt=False) == unhexlify(output_data['cbor'])
