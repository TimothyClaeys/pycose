from binascii import unhexlify

from pytest import fixture, mark, skip

from pycose import EncMessage, CoseMessage
from pycose.algorithms import AlgorithmIDs
from pycose.cosebase import HeaderKeys
from pycose.keys.cosekey import KeyOps, CoseKey, KTY
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP
from pycose.keys.symmetric import SymmetricKey
from pycose.recipient import CoseRecipient, SuppPubInfo, PartyInfo, CoseKDFContext
from tests.conftest import generic_test_setup, extract_protected_header, extract_unprotected_header, \
    extract_unsent_nonce, create_cose_key


@fixture
def setup_encrypt_tests(encrypt_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_test_input)


@mark.encoding
def test_encrypt_encoding(setup_encrypt_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_tests

    m = EncMessage(
        phdr=extract_protected_header(test_input, 'enveloped'),
        uhdr=extract_unprotected_header(test_input, 'enveloped'),
        payload=test_input['plaintext'].encode('utf-8'),
        external_aad=unhexlify(test_input['enveloped'].get('external', b'')))

    nonce = extract_unsent_nonce(test_input, 'enveloped')

    # check for external data and verify internal _enc_structure
    assert m._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # set up the CEK.
    m.key = create_cose_key(SymmetricKey, test_input['enveloped']['recipients'][0]['key'], usage=KeyOps.ENCRYPT)
    assert m.key.key_bytes == unhexlify(test_intermediate['CEK_hex'])

    # create the recipients
    r_info = test_input['enveloped']['recipients'][0]
    recipient = CoseRecipient(
        phdr=r_info.get('protected', {}),
        uhdr=r_info.get('unprotected', {}),
        payload=m.key.key_bytes,
        key=m.key
    )

    m.recipients.append(recipient)

    # verify encoding (with automatic encryption)
    if fail:
        assert m.encode(encrypt=True, nonce=nonce) != unhexlify(test_output)
    else:
        # (1) test encoding without specifying recipient crypto params
        assert m.encode(encrypt=True, nonce=nonce) == unhexlify(test_output)

        # (2)
        assert m.encode(encrypt=True, nonce=nonce,
                        crypto_params=((True, AlgorithmIDs.DIRECT, None, None),)) == unhexlify(test_output)


@mark.decoding
def test_encrypt_decoding(setup_encrypt_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_tests

    if fail:
        skip("invalid test input")

    # parse initial message
    msg = CoseMessage.decode(unhexlify(test_output))

    # verify parsed protected header
    assert msg.phdr == extract_protected_header(test_input, 'enveloped')
    assert msg.uhdr == extract_unprotected_header(test_input, 'enveloped')

    nonce = extract_unsent_nonce(test_input, 'enveloped')

    key = create_cose_key(SymmetricKey, test_input['enveloped']["recipients"][0]["key"], usage=KeyOps.DECRYPT)
    assert key.key_bytes == unhexlify(test_intermediate['CEK_hex'])

    # look for external data and verify internal enc_structure
    msg.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert msg._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # verify recipients
    assert len(msg.recipients) == 1
    assert msg.recipients[0].phdr == test_input['enveloped']['recipients'][0].get('protected', {})
    assert msg.recipients[0].uhdr == test_input['enveloped']['recipients'][0].get('unprotected', {})

    # (1) verify decryption
    nonce = nonce if nonce is not None else unhexlify(test_input['rng_stream'][0].encode('utf-8'))
    assert msg.decrypt(nonce=nonce, key=key) == test_input['plaintext'].encode('utf-8')

    # re-encode and verify we are back where we started
    assert msg.encode(encrypt=False) == unhexlify(test_output)


@fixture
def setup_encrypt_ecdh_direct_tests(encrypt_ecdh_direct_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_ecdh_direct_test_input)


@mark.encoding
@mark.decoding
def test_encrypt_ecdh_direct_decode_encode(setup_encrypt_ecdh_direct_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_ecdh_direct_tests

    # DECODING

    # parse message and test for headers
    md = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == extract_protected_header(test_input, 'enveloped')
    assert md.uhdr == extract_unprotected_header(test_input, 'enveloped', 1)

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # verify the receiver and set up the keying material
    recipients = test_input['enveloped']['recipients']
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

        u = PartyInfo(nonce=unhexlify(test_input['rng_stream'][0]))
    else:
        # ephemeral key pair
        # verify if it is really ephemeral and that we are only using EC2 CoseKeys
        assert HeaderKeys.EPHEMERAL_KEY in md.recipients[0].uhdr
        assert md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][CoseKey.Common.KTY] == KTY.EC2

        # create CoseKey object for the sender key
        sender_key = EC2(
            crv=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][EC2.EC2Prm.CRV],
            x=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][EC2.EC2Prm.X],
            y=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][EC2.EC2Prm.Y]
        )

        u = PartyInfo()

    # create context KDF
    v = PartyInfo()
    s = SuppPubInfo(len(test_intermediate['CEK_hex']) * 4, md.recipients[0].encode_phdr())
    kdf_ctx = CoseKDFContext(md.phdr[HeaderKeys.ALG], u, v, s)
    assert kdf_ctx.encode() == unhexlify(test_intermediate['recipients'][0]['Context_hex'])

    secret, kek = CoseRecipient.derive_kek(receiver_static_key, sender_key, md.recipients[0].phdr[HeaderKeys.ALG],
                                           kdf_ctx, expose_secret=True)
    assert secret == unhexlify(test_intermediate['recipients'][0]['Secret_hex'])
    assert kek == unhexlify(test_intermediate['CEK_hex'])

    md.key = SymmetricKey(k=kek)
    assert md.decrypt() == test_input['plaintext'].encode('utf-8')

    # ENCODING

    me = EncMessage(phdr=test_input['enveloped'].get("protected", {}),
                    uhdr=test_input['enveloped'].get("unprotected", {}),
                    payload=test_input['plaintext'].encode('utf-8'))

    if 'rng_stream' in test_input:
        me.uhdr_update({HeaderKeys.IV: unhexlify(test_input['rng_stream'][1])})

    # Set up recipients and keys
    recipients = test_input['enveloped'].get('recipients', [])
    if len(recipients) > 1 or len(recipients) == 0:
        raise NotImplementedError("Can't deal with this now")
    rcpt = recipients[0]

    if 'sender_key' in rcpt:
        r1 = CoseRecipient(phdr=rcpt.get('protected', {}))
        r1.uhdr_update({HeaderKeys.STATIC_KEY: sender_key.encode('crv', 'x', 'y')})
        r1.uhdr_update(rcpt.get('unprotected', {}))
        r1.uhdr_update({HeaderKeys.PARTY_U_NONCE: unhexlify(test_input['rng_stream'][0])})
    else:
        r1 = CoseRecipient(phdr=rcpt.get('protected', {}))
        r1.uhdr_update({HeaderKeys.EPHEMERAL_KEY: sender_key.encode('crv', 'x', 'y')})
        r1.uhdr_update(rcpt.get('unprotected', {}))

    # append the first and only recipient
    me.recipients.append(r1)

    # set up cek
    me.key = SymmetricKey(k=kek)

    # without sorting probably does not match because the order of the recipient elements is not the same
    assert sorted(me.encode()) == sorted(unhexlify(test_output))


@fixture
def setup_encrypt_ecdh_wrap_tests(encrypt_ecdh_wrap_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_ecdh_wrap_test_input)


@mark.decoding
def test_encrypt_ecdh_wrap_decode(setup_encrypt_ecdh_wrap_tests: tuple):
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_ecdh_wrap_tests
    # DECODING

    # parse message and test for headers
    md = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == test_input['enveloped'].get('protected', {})

    unprotected = test_input['enveloped'].get('unprotected', {})
    if 'rng_stream' in test_input:
        unprotected.update({HeaderKeys.IV: unhexlify(test_input['rng_stream'][1])})
    assert md.uhdr == unprotected

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # verify the receiver and set up the keying material
    recipients = test_input['enveloped'].get('recipients', [])
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
        assert HeaderKeys.EPHEMERAL_KEY in md.recipients[0].uhdr
        assert md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][CoseKey.Common.KTY] == KTY.EC2

        # create CoseKey object for the sender key
        sender_key = EC2(
            crv=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][EC2.EC2Prm.CRV],
            x=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][EC2.EC2Prm.X],
            y=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][EC2.EC2Prm.Y]
        )

    # create context KDF
    v = PartyInfo()
    u = PartyInfo()
    s = SuppPubInfo(len(test_intermediate['recipients'][0]['KEK_hex']) * 4, md.recipients[0].encode_phdr())
    if md.recipients[0].phdr[HeaderKeys.ALG] in {AlgorithmIDs.ECDH_ES_A192KW, AlgorithmIDs.ECDH_SS_A192KW}:
        kdf_ctx = CoseKDFContext(AlgorithmIDs.A192KW, u, v, s)
    elif md.recipients[0].phdr[HeaderKeys.ALG] in {AlgorithmIDs.ECDH_ES_A128KW, AlgorithmIDs.ECDH_SS_A128KW}:
        kdf_ctx = CoseKDFContext(AlgorithmIDs.A128KW, u, v, s)
    elif md.recipients[0].phdr[HeaderKeys.ALG] in {AlgorithmIDs.ECDH_ES_A256KW, AlgorithmIDs.ECDH_SS_A256KW}:
        kdf_ctx = CoseKDFContext(AlgorithmIDs.A256KW, u, v, s)
    else:
        raise ValueError("Missed an algorithm?")

    assert kdf_ctx.encode() == unhexlify(test_intermediate['recipients'][0]['Context_hex'])

    secret, kek = CoseRecipient.derive_kek(
        receiver_static_key,
        sender_key,
        md.recipients[0].phdr[HeaderKeys.ALG],
        kdf_ctx,
        expose_secret=True
    )
    assert secret == unhexlify(test_intermediate['recipients'][0]['Secret_hex'])
    assert kek == unhexlify(test_intermediate['recipients'][0]['KEK_hex'])

    r1 = md.recipients[0]
    assert r1.decrypt(key=SymmetricKey(k=kek)) == unhexlify(test_intermediate['CEK_hex'])

    # try to decrypt without the key set
    try:
        r1.decrypt()
    except AttributeError:
        pass

    md.recipients[0].key = SymmetricKey(k=kek)
    cek = r1.decrypt(key=SymmetricKey(k=kek))
    assert cek == unhexlify(test_intermediate['CEK_hex'])

    assert md.decrypt(key=SymmetricKey(k=cek)) == test_input['plaintext'].encode('utf-8')


@fixture
def setup_encrypt_x25519_direct_tests(encrypt_x25519_direct_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_x25519_direct_test_input)


@mark.decoding
def test_encrypt_x25519_wrap_decode(setup_encrypt_x25519_direct_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_x25519_direct_tests
    # DECODING

    # parse message and test for headers
    md = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == test_input['enveloped'].get('protected', {})

    unprotected = test_input['enveloped'].get('unprotected', {})
    if 'rng_stream' in test_input:
        unprotected.update({HeaderKeys.IV: unhexlify(test_input['rng_stream'][1])})
    assert md.uhdr == unprotected

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    rcpt = test_input['enveloped']['recipients'][0]
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

        u = PartyInfo(nonce=unhexlify(test_input['rng_stream'][0]))
    else:
        # ephemeral key pair
        # verify if it is really ephemeral and that we are only using EC2 CoseKeys
        assert HeaderKeys.EPHEMERAL_KEY in md.recipients[0].uhdr
        assert md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][CoseKey.Common.KTY] == KTY.OKP

        # create CoseKey object for the sender key
        sender_key = OKP(
            crv=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][OKP.OKPPrm.CRV],
            x=md.recipients[0].uhdr[HeaderKeys.EPHEMERAL_KEY][OKP.OKPPrm.X],
        )
        u = PartyInfo()

    # create context KDF
    s = SuppPubInfo(len(test_intermediate['CEK_hex']) * 4, md.recipients[0].encode_phdr())
    kdf_ctx = CoseKDFContext(md.phdr[HeaderKeys.ALG], u, PartyInfo(), s)
    assert kdf_ctx.encode() == unhexlify(test_intermediate['recipients'][0]['Context_hex'])

    secret, kek = CoseRecipient.derive_kek(
        receiver_static_key,
        sender_key,
        md.recipients[0].phdr[HeaderKeys.ALG],
        kdf_ctx,
        expose_secret=True
    )

    assert secret == unhexlify(test_intermediate['recipients'][0]['Secret_hex'])
    assert kek == unhexlify(test_intermediate['CEK_hex'])

    md.key = SymmetricKey(k=kek)
    assert md.decrypt() == test_input['plaintext'].encode('utf-8')


@fixture
def setup_encrypt_triple_layer_tests(encrypt_triple_layer_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_triple_layer_test_input)


@mark.decoding
def test_encrypt_triple_layer_decode(setup_encrypt_triple_layer_tests: tuple):
    # TODO: fails because the y coordinate of the third later is 'false' ?
    skip("not implemented")


@fixture
def setup_encrypt_hkdf_hmac_direct_tests(encrypt_hkdf_hmac_direct_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_hkdf_hmac_direct_test_input)


def test_encrypt_hkdf_hmac_direct_decode(setup_encrypt_hkdf_hmac_direct_tests: tuple) -> None:
    title, test_input, test_output, test_intermediate, fail = setup_encrypt_hkdf_hmac_direct_tests

    # parse message and test for headers
    md = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == test_input['enveloped'].get('protected', {})

    unprotected = test_input['enveloped'].get('unprotected', {})
    if 'rng_stream' in test_input:
        unprotected.update({HeaderKeys.IV: unhexlify(test_input['rng_stream'][0])})
    assert md.uhdr == unprotected

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    rcpt = test_input['enveloped']['recipients'][0]
    assert md.recipients[0].phdr == rcpt.get('protected', {})

    # create HKDF contect
    v = PartyInfo(
        identity=md.recipients[0].uhdr.get(HeaderKeys.PARTY_V_IDENTITY),
        nonce=md.recipients[0].uhdr.get(HeaderKeys.PARTY_V_NONCE),
        other=md.recipients[0].uhdr.get(HeaderKeys.PARTY_V_OTHER))
    u = PartyInfo(
        identity=md.recipients[0].uhdr.get(HeaderKeys.PARTY_U_IDENTITY),
        nonce=md.recipients[0].uhdr.get(HeaderKeys.PARTY_U_NONCE),
        other=md.recipients[0].uhdr.get(HeaderKeys.PARTY_U_OTHER))
    public_data = test_input['enveloped']['recipients'][0].get('unsent', {}).get('pub_other')
    s = SuppPubInfo(
        len(test_intermediate['CEK_hex']) * 4,
        md.recipients[0].encode_phdr(),
        public_data.encode('utf-8') if public_data is not None else public_data)
    priv_data = test_input['enveloped']['recipients'][0].get('unsent', {}).get('priv_other')
    hkdf_context = CoseKDFContext(md.phdr[HeaderKeys.ALG],
                                  u, v, s,
                                  priv_data.encode('utf') if priv_data is not None else priv_data)
    hkdf_context_encoded = hkdf_context.encode()
    assert hkdf_context_encoded == unhexlify(test_intermediate["recipients"][0]['Context_hex'])

    # set shared secret key
    shared_secret = SymmetricKey(
        k=CoseKey.base64decode(test_input['enveloped']['recipients'][0]['key'][SymmetricKey.SymPrm.K]))

    kek = md.recipients[0].derive_kek(
        shared_secret,
        alg=md.recipients[0].phdr[HeaderKeys.ALG],
        context=hkdf_context,
        salt=md.recipients[0].uhdr.get(HeaderKeys.SALT)
    )

    assert kek == unhexlify(test_intermediate["CEK_hex"])
    assert md.decrypt(key=SymmetricKey(k=kek)) == test_input['plaintext'].encode('utf-8')
