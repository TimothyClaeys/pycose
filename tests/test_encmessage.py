import os
from binascii import unhexlify

import pytest

from pycose import EncMessage, CoseMessage
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.cosekey import SymmetricKey, KeyOps, CoseKey, EC2
from pycose.crypto import PartyInfo, SuppPubInfo, CoseKDFContext
from pycose.recipient import CoseRecipient
from tests.conftest import aes_gcm_examples, enveloped_tests, ecdh_direct_examples

test_cases_1 = [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples) if '-enc-' not in v] + \
               [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples) if '-enc-' not in v] + \
               [os.path.join(enveloped_tests, v) for v in os.listdir(enveloped_tests)]

test_cases_2 = [os.path.join(ecdh_direct_examples, v) for v in os.listdir(ecdh_direct_examples)]


@pytest.mark.parametrize('encrypt_test_cases', test_cases_1, indirect=['encrypt_test_cases'])
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
@pytest.mark.parametrize('encrypt_test_cases', test_cases_1, indirect=['encrypt_test_cases'])
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


@pytest.mark.decoding
@pytest.mark.parametrize('ecdh_direct_enc_test_cases', test_cases_2, indirect=['ecdh_direct_enc_test_cases'])
def test_encrypt_ecdh_direct_kek_encoding(ecdh_direct_enc_test_cases: dict) -> None:
    try:
        input_data = ecdh_direct_enc_test_cases['input']
        enveloped = input_data['enveloped']
    except (TypeError, KeyError):
        return pytest.skip("Invalid parameters")

    m = EncMessage(payload=input_data['plaintext'].encode('utf-8'))
    m.phdr = enveloped.get('protected', {})
    m.uhdr = enveloped.get('unprotected', {})

    nonce = None
    if 'rng_stream' in input_data:
        m.uhdr_update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][0])})
    else:
        if 'unsent' in enveloped:
            nonce = unhexlify(enveloped.get('unsent').get('IV_hex'))

    # check for external data and verify internal _enc_structure
    m.external_aad = unhexlify(enveloped.get('external', b''))
    assert m._enc_structure == unhexlify(ecdh_direct_enc_test_cases['intermediates']['AAD_hex'])

    # setting up the keys for the sender and receiver and create the recipient
    recipients = enveloped.get('recipients', [])
    if len(recipients) > 1 or len(recipients) == 0:
        raise NotImplementedError("Can't deal with this now")

    rcpt = recipients[0]

    r = CoseRecipient(phdr=rcpt.get("protected", {}), uhdr=rcpt.get("unprotected", {}))

    receiver_key = EC2(
        kid=rcpt['key']['kid'].encode('utf-8'),
        crv=rcpt['key']['crv'],
        x=CoseKey.base64decode(rcpt['key']['x']),
        y=CoseKey.base64decode(rcpt['key']['y'])
    )

    if 'sender_key' in rcpt:
        # static keys, skip for now
        return pytest.skip('static keys, skip for now')

    sender_key = EC2(
        kid=rcpt['key']['kid'].encode('utf-8'),
        crv=rcpt['key']['crv'],
        d=unhexlify(input_data['rng_stream'][0])
    )

    # create context KDF
    u = PartyInfo()
    v = PartyInfo()
    s = SuppPubInfo(len(ecdh_direct_enc_test_cases['intermediates']['CEK_hex']) * 4, r.encode_phdr())
    kdf_ctx = CoseKDFContext(m.phdr[CoseHeaderParam.ALG], u, v, s)
    assert kdf_ctx.encode() == unhexlify(ecdh_direct_enc_test_cases['intermediates']['recipients'][0]['Context_hex'])

    secret, kek = r.derive_kek(private_key=sender_key, public_key=receiver_key, context=kdf_ctx, expose_secret=True)
    # assert secret == unhexlify(ecdh_direct_enc_test_cases['intermediates']['recipients'][0]['Secret_hex'])
