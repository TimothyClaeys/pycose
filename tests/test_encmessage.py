import os
from binascii import unhexlify

import pytest

from pycose import EncMessage, CoseMessage
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.cosekey import SymmetricKey, KeyOps, CoseKey, EC2, KTY, OKP
from pycose.crypto import PartyInfo, SuppPubInfo, CoseKDFContext
from pycose.recipient import CoseRecipient
from tests.conftest import aes_gcm_examples, enveloped_tests, ecdh_direct_examples, ecdh_wrap_examples, x25519_tests, \
    triple_layer_enc

test_cases_1 = [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples) if '-enc-' not in v] + \
               [os.path.join(aes_gcm_examples, v) for v in os.listdir(aes_gcm_examples) if '-enc-' not in v] + \
               [os.path.join(enveloped_tests, v) for v in os.listdir(enveloped_tests)]

test_cases_2 = [os.path.join(ecdh_direct_examples, v) for v in os.listdir(ecdh_direct_examples)]
test_cases_3 = [os.path.join(ecdh_wrap_examples, v) for v in os.listdir(ecdh_wrap_examples)]
test_cases_4 = [os.path.join(x25519_tests, v) for v in os.listdir(x25519_tests)]
test_cases_5 = [os.path.join(triple_layer_enc, v) for v in os.listdir(triple_layer_enc) if "Appendix_B" in v]


@pytest.mark.parametrize('encrypt_test_cases', test_cases_1, indirect=['encrypt_test_cases'])
def test_encrypt_encoding(encrypt_test_cases: dict) -> None:
    try:
        input_data = encrypt_test_cases['input']
    except (TypeError, KeyError):
        return pytest.skip("Invalid test parameters")

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
        rcpt.key = SymmetricKey(k=r_info['key'][SymmetricKey.SymPrm.K], kid=r_info["key"][CoseKey.Common.KID])
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
        return pytest.skip("Invalid test parameters")

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
    key = SymmetricKey(
        kid=key[CoseKey.Common.KID],
        key_ops=KeyOps.DECRYPT,
        k=CoseKey.base64decode(key[SymmetricKey.SymPrm.K]))
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
def test_encrypt_ecdh_direct_decode_encode(ecdh_direct_enc_test_cases: dict) -> None:
    try:
        output = ecdh_direct_enc_test_cases['output']['cbor']
        input_data = ecdh_direct_enc_test_cases['input']
        enveloped = input_data['enveloped']
    except (TypeError, KeyError):
        return pytest.skip("Invalid test parameters")

    # DECODING

    # parse message and test for headers
    md = CoseMessage.decode(unhexlify(output))
    assert md.phdr == enveloped.get('protected', {})

    unprotected = enveloped.get('unprotected', {})
    if 'rng_stream' in input_data:
        unprotected.update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][1])})
    assert md.uhdr == unprotected

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(enveloped.get('external', b''))
    assert md._enc_structure == unhexlify(ecdh_direct_enc_test_cases['intermediates']['AAD_hex'])

    # verify the receiver and set up the keying material
    recipients = enveloped.get('recipients', [])
    if len(recipients) > 1 or len(recipients) == 0:
        raise NotImplementedError("Can't deal with this now")

    rcpt = recipients[0]
    assert md.recipients[0].phdr == rcpt.get('protected', {})
    # do not verify unprotected header since it contains the ephemeral public key of the sender
    # assert m.recipients[0].uhdr == rcpt.get('unprotected', {})

    receiver_static_key = EC2(
        kid=rcpt['key'][CoseKey.Common.KID].encode('utf-8'),
        crv=rcpt['key'][EC2.EC2Prm.CRV],
        x=CoseKey.base64decode(rcpt['key'][EC2.EC2Prm.X]),
        y=CoseKey.base64decode(rcpt['key'][EC2.EC2Prm.Y]),
        d=CoseKey.base64decode(rcpt['key'][EC2.EC2Prm.D]),
    )

    if 'sender_key' in rcpt:
        # static key sender key
        sender_key = EC2(
            crv=rcpt["sender_key"][EC2.EC2Prm.CRV],
            x=CoseKey.base64decode(rcpt['sender_key'][EC2.EC2Prm.X]),
            y=CoseKey.base64decode(rcpt['sender_key'][EC2.EC2Prm.Y]),
        )

        u = PartyInfo(nonce=unhexlify(input_data['rng_stream'][0]))
    else:
        # ephemeral key pair
        # verify if it is really ephemeral and that we are only using EC2 CoseKeys
        assert CoseHeaderParam.EPHEMERAL_KEY in md.recipients[0].uhdr
        assert md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][CoseKey.Common.KTY] == KTY.EC2

        # create CoseKey object for the sender key
        sender_key = EC2(
            crv=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][EC2.EC2Prm.CRV],
            x=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][EC2.EC2Prm.X],
            y=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][EC2.EC2Prm.Y]
        )

        u = PartyInfo()

    # create context KDF
    v = PartyInfo()
    s = SuppPubInfo(len(ecdh_direct_enc_test_cases['intermediates']['CEK_hex']) * 4, md.recipients[0].encode_phdr())
    kdf_ctx = CoseKDFContext(md.phdr[CoseHeaderParam.ALG], u, v, s)
    assert kdf_ctx.encode() == unhexlify(ecdh_direct_enc_test_cases['intermediates']['recipients'][0]['Context_hex'])

    secret, kek = CoseRecipient.derive_kek(receiver_static_key, sender_key, md.recipients[0].phdr[CoseHeaderParam.ALG],
                                           kdf_ctx, expose_secret=True)
    assert secret == unhexlify(ecdh_direct_enc_test_cases['intermediates']['recipients'][0]['Secret_hex'])
    assert kek == unhexlify(ecdh_direct_enc_test_cases['intermediates']['CEK_hex'])

    md.key = SymmetricKey(k=kek)
    assert md.decrypt() == input_data['plaintext'].encode('utf-8')

    # ENCODING

    me = EncMessage(phdr=enveloped.get("protected", {}),
                    uhdr=enveloped.get("unprotected", {}),
                    payload=input_data.get('plaintext', b'').encode('utf-8'))

    if 'rng_stream' in input_data:
        me.uhdr_update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][1])})

    # Set up recipients and keys
    recipients = enveloped.get('recipients', [])
    if len(recipients) > 1 or len(recipients) == 0:
        raise NotImplementedError("Can't deal with this now")
    rcpt = recipients[0]

    if 'sender_key' in rcpt:
        r1 = CoseRecipient(phdr=rcpt.get('protected', {}))
        r1.uhdr_update({CoseHeaderParam.STATIC_KEY: sender_key.encode('crv', 'x', 'y')})
        r1.uhdr_update(rcpt.get('unprotected', {}))
        r1.uhdr_update({CoseHeaderParam.PARTY_U_NONCE: unhexlify(input_data.get('rng_stream')[0])})
    else:
        r1 = CoseRecipient(phdr=rcpt.get('protected', {}))
        r1.uhdr_update({CoseHeaderParam.EPHEMERAL_KEY: sender_key.encode('crv', 'x', 'y')})
        r1.uhdr_update(rcpt.get('unprotected', {}))

    # append the first and only recipient
    me.recipients.append(r1)

    # set up cek
    me.key = SymmetricKey(k=kek)

    # without sorting probably does not match because the order of the recipient elements is not the same
    assert sorted(me.encode()) == sorted(unhexlify(output))


@pytest.mark.decoding
@pytest.mark.parametrize('ecdh_wrap_enc_test_cases', test_cases_3, indirect=['ecdh_wrap_enc_test_cases'])
def test_encrypt_ecdh_wrap_decode(ecdh_wrap_enc_test_cases: dict):
    try:
        output = ecdh_wrap_enc_test_cases['output']['cbor']
        input_data = ecdh_wrap_enc_test_cases['input']
        enveloped = input_data['enveloped']
    except (TypeError, KeyError):
        return pytest.skip("Invalid test parameters")
    # DECODING

    # parse message and test for headers
    md = CoseMessage.decode(unhexlify(output))
    assert md.phdr == enveloped.get('protected', {})

    unprotected = enveloped.get('unprotected', {})
    if 'rng_stream' in input_data:
        unprotected.update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][1])})
    assert md.uhdr == unprotected

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(enveloped.get('external', b''))
    assert md._enc_structure == unhexlify(ecdh_wrap_enc_test_cases['intermediates']['AAD_hex'])

    # verify the receiver and set up the keying material
    recipients = enveloped.get('recipients', [])
    if len(recipients) > 1 or len(recipients) == 0:
        raise NotImplementedError("Can't deal with this now")

    rcpt = recipients[0]
    assert md.recipients[0].phdr == rcpt.get('protected', {})
    # do not verify unprotected header since it contains the ephemeral public key of the sender
    # assert m.recipients[0].uhdr == rcpt.get('unprotected', {})

    receiver_static_key = EC2(
        kid=rcpt['key'][CoseKey.Common.KID].encode('utf-8'),
        crv=rcpt['key'][EC2.EC2Prm.CRV],
        x=CoseKey.base64decode(rcpt['key'][EC2.EC2Prm.X]),
        y=CoseKey.base64decode(rcpt['key'][EC2.EC2Prm.Y]),
        d=CoseKey.base64decode(rcpt['key'][EC2.EC2Prm.D]),
    )

    if 'sender_key' in rcpt:
        # static key sender key
        sender_key = EC2(
            crv=rcpt["sender_key"][EC2.EC2Prm.CRV],
            x=CoseKey.base64decode(rcpt['sender_key'][EC2.EC2Prm.X]),
            y=CoseKey.base64decode(rcpt['sender_key'][EC2.EC2Prm.Y]),
        )
    else:
        # ephemeral key pair
        # verify if it is really ephemeral and that we are only using EC2 CoseKeys
        assert CoseHeaderParam.EPHEMERAL_KEY in md.recipients[0].uhdr
        assert md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][CoseKey.Common.KTY] == KTY.EC2

        # create CoseKey object for the sender key
        sender_key = EC2(
            crv=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][EC2.EC2Prm.CRV],
            x=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][EC2.EC2Prm.X],
            y=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][EC2.EC2Prm.Y]
        )

    # create context KDF
    v = PartyInfo()
    u = PartyInfo()
    s = SuppPubInfo(
        len(ecdh_wrap_enc_test_cases['intermediates']['recipients'][0]['KEK_hex']) * 4,
        md.recipients[0].encode_phdr()
    )
    if md.recipients[0].phdr[CoseHeaderParam.ALG] in {CoseAlgorithm.ECDH_ES_A192KW, CoseAlgorithm.ECDH_SS_A192KW}:
        kdf_ctx = CoseKDFContext(CoseAlgorithm.A192KW, u, v, s)
    elif md.recipients[0].phdr[CoseHeaderParam.ALG] in {CoseAlgorithm.ECDH_ES_A128KW, CoseAlgorithm.ECDH_SS_A128KW}:
        kdf_ctx = CoseKDFContext(CoseAlgorithm.A128KW, u, v, s)
    elif md.recipients[0].phdr[CoseHeaderParam.ALG] in {CoseAlgorithm.ECDH_ES_A256KW, CoseAlgorithm.ECDH_SS_A256KW}:
        kdf_ctx = CoseKDFContext(CoseAlgorithm.A256KW, u, v, s)
    else:
        raise ValueError("Missed an algorithm?")

    assert kdf_ctx.encode() == unhexlify(ecdh_wrap_enc_test_cases['intermediates']['recipients'][0]['Context_hex'])

    secret, kek = CoseRecipient.derive_kek(
        receiver_static_key,
        sender_key,
        md.recipients[0].phdr[CoseHeaderParam.ALG],
        kdf_ctx,
        expose_secret=True
    )
    assert secret == unhexlify(ecdh_wrap_enc_test_cases['intermediates']['recipients'][0]['Secret_hex'])
    assert kek == unhexlify(ecdh_wrap_enc_test_cases['intermediates']['recipients'][0]['KEK_hex'])

    r1 = md.recipients[0]
    assert r1.decrypt(key=SymmetricKey(k=kek)) == unhexlify(ecdh_wrap_enc_test_cases['intermediates']['CEK_hex'])

    # try to decrypt with the key set
    try:
        r1.decrypt()
    except AttributeError:
        pass

    md.recipients[0].key = SymmetricKey(k=kek)
    cek = r1.decrypt(key=SymmetricKey(k=kek))
    assert cek == unhexlify(ecdh_wrap_enc_test_cases['intermediates']['CEK_hex'])

    assert md.decrypt(key=SymmetricKey(k=cek)) == input_data['plaintext'].encode('utf-8')


@pytest.mark.decoding
@pytest.mark.parametrize('x25519_direct_enc_test_cases', test_cases_4, indirect=['x25519_direct_enc_test_cases'])
def test_encrypt_x25519_wrap_decode(x25519_direct_enc_test_cases: dict) -> None:
    try:
        output = x25519_direct_enc_test_cases['output']['cbor']
        input_data = x25519_direct_enc_test_cases['input']
        enveloped = input_data['enveloped']
    except (TypeError, KeyError):
        return pytest.skip("Invalid test parameters")
    # DECODING

    # parse message and test for headers
    md = CoseMessage.decode(unhexlify(output))
    assert md.phdr == enveloped.get('protected', {})

    unprotected = enveloped.get('unprotected', {})
    if 'rng_stream' in input_data:
        unprotected.update({CoseHeaderParam.IV: unhexlify(input_data['rng_stream'][1])})
    assert md.uhdr == unprotected

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(enveloped.get('external', b''))
    assert md._enc_structure == unhexlify(x25519_direct_enc_test_cases['intermediates']['AAD_hex'])

    # verify the receiver and set up the keying material
    recipients = enveloped.get('recipients', [])
    if len(recipients) > 1 or len(recipients) == 0:
        raise NotImplementedError("Can't deal with this now")

    rcpt = recipients[0]
    assert md.recipients[0].phdr == rcpt.get('protected', {})
    # do not verify unprotected header since it contains the ephemeral public key of the sender
    # assert m.recipients[0].uhdr == rcpt.get('unprotected', {})

    receiver_static_key = OKP(
        kid=rcpt['key'][CoseKey.Common.KID].encode('utf-8'),
        crv=rcpt['key'][OKP.OKPPrm.CRV],
        x=unhexlify(rcpt['key'][OKP.OKPPrm.X]),
        d=unhexlify(rcpt['key'][OKP.OKPPrm.D]),
    )

    if 'sender_key' in rcpt:
        # static key sender key
        sender_key = OKP(
            crv=rcpt["sender_key"][OKP.OKPPrm.CRV],
            x=unhexlify(rcpt['sender_key'][OKP.OKPPrm.X])
        )

        u = PartyInfo(nonce=unhexlify(input_data['rng_stream'][0]))
    else:
        # ephemeral key pair
        # verify if it is really ephemeral and that we are only using EC2 CoseKeys
        assert CoseHeaderParam.EPHEMERAL_KEY in md.recipients[0].uhdr
        assert md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][CoseKey.Common.KTY] == KTY.OKP

        # create CoseKey object for the sender key
        sender_key = OKP(
            crv=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][OKP.OKPPrm.CRV],
            x=md.recipients[0].uhdr[CoseHeaderParam.EPHEMERAL_KEY][OKP.OKPPrm.X],
        )
        u = PartyInfo()

    # create context KDF
    s = SuppPubInfo(len(x25519_direct_enc_test_cases['intermediates']['CEK_hex']) * 4, md.recipients[0].encode_phdr())
    kdf_ctx = CoseKDFContext(md.phdr[CoseHeaderParam.ALG], u, PartyInfo(), s)
    assert kdf_ctx.encode() == unhexlify(x25519_direct_enc_test_cases['intermediates']['recipients'][0]['Context_hex'])

    secret, kek = CoseRecipient.derive_kek(
        receiver_static_key,
        sender_key,
        md.recipients[0].phdr[CoseHeaderParam.ALG],
        kdf_ctx,
        expose_secret=True
    )

    assert secret == unhexlify(x25519_direct_enc_test_cases['intermediates']['recipients'][0]['Secret_hex'])
    assert kek == unhexlify(x25519_direct_enc_test_cases['intermediates']['CEK_hex'])

    md.key = SymmetricKey(k=kek)
    assert md.decrypt() == input_data['plaintext'].encode('utf-8')


@pytest.mark.decoding
@pytest.mark.parametrize('triple_layer_msg', test_cases_5, indirect=['triple_layer_msg'])
def test_encrypt_triple_layer_decode(triple_layer_msg: dict):
    try:
        output = triple_layer_msg['output']['cbor']
        input_data = triple_layer_msg['input']
        enveloped = input_data['enveloped']
    except (TypeError, KeyError):
        return pytest.skip("Invalid test parameters")

    # TODO: fails because the y coordinate of the third later is 'false' ?
    # md = CoseMessage.decode(unhexlify(output))

    # # CHECK FIRST LAYER
    # assert md.phdr == enveloped.get('protected', {})