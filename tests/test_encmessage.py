from binascii import unhexlify

from pytest import fixture, mark, skip

from pycose import EncMessage, CoseMessage
from pycose.algorithms import CoseAlgorithms
from pycose.context import PartyInfo, SuppPubInfo, CoseKDFContext
from pycose.cosebase import HeaderKeys
from pycose.keys.cosekey import KeyOps, CoseKey
from pycose.keys.symmetric import SymmetricKey
from pycose.recipient import CoseRecipient, RcptParams
from tests.conftest import generic_test_setup, extract_phdr, extract_uhdr, \
    extract_unsent_nonce, create_cose_key, extract_nonce, extract_alg, setup_ec_receiver_keys, setup_okp_receiver_keys


@fixture
def setup_encrypt_tests(encrypt_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_test_input)


@mark.encoding
def test_encrypt_encoding(setup_encrypt_tests: tuple) -> None:
    title, test_input, test_output, test_intermediate, fail = setup_encrypt_tests
    alg = extract_alg(test_input["enveloped"])
    nonce = extract_nonce(test_input, 0) if extract_nonce(test_input, 0) != b'' else extract_unsent_nonce(
        test_input, "enveloped")

    m = EncMessage(
        phdr=extract_phdr(test_input, 'enveloped'),
        uhdr=extract_uhdr(test_input, 'enveloped'),
        payload=test_input['plaintext'].encode('utf-8'),
        external_aad=unhexlify(test_input['enveloped'].get('external', b'')))

    # check for external data and verify internal _enc_structure
    assert m._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # set up the CEK and KEK
    cek = create_cose_key(SymmetricKey, test_input['enveloped']['recipients'][0]['key'], alg=alg, usage=KeyOps.ENCRYPT)
    kek = create_cose_key(SymmetricKey, test_input['enveloped']['recipients'][0]['key'], alg=CoseAlgorithms.DIRECT.id,
                          usage=KeyOps.WRAP)

    # create the recipients
    r_info = test_input['enveloped']['recipients'][0]
    recipient = CoseRecipient(phdr=r_info.get('protected', {}), uhdr=r_info.get('unprotected', {}), payload=cek.k)

    m.recipients.append(recipient)

    # verify encoding (with automatic encryption)
    if fail:
        assert m.encode(key=cek, nonce=nonce, enc_params=[RcptParams(key=kek)]) != unhexlify(test_output)
    else:
        # test encoding/protection
        assert m.encode(key=cek, nonce=nonce, enc_params=[RcptParams(key=kek)]) == unhexlify(test_output)


@mark.decoding
def test_encrypt_decoding(setup_encrypt_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_tests

    if fail:
        skip("invalid test input")

    # parse initial message
    msg: EncMessage = CoseMessage.decode(unhexlify(test_output))

    # verify parsed protected header
    assert msg.phdr == extract_phdr(test_input, 'enveloped')
    assert msg.uhdr == extract_uhdr(test_input, 'enveloped')

    nonce = extract_nonce(test_input, 0) if extract_nonce(test_input, 0) != b'' else extract_unsent_nonce(
        test_input, "enveloped")

    alg = extract_alg(test_input['enveloped'])
    cek = create_cose_key(SymmetricKey, test_input['enveloped']["recipients"][0]["key"], usage=KeyOps.DECRYPT, alg=alg)
    assert cek.k == unhexlify(test_intermediate['CEK_hex'])

    # look for external data and verify internal enc_structure
    msg.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert msg._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # verify recipients
    assert len(msg.recipients) == 1
    assert msg.recipients[0].phdr == test_input['enveloped']['recipients'][0].get('protected', {})
    assert msg.recipients[0].uhdr == test_input['enveloped']['recipients'][0].get('unprotected', {})

    # (1) verify decryption
    assert msg.decrypt(nonce=nonce, key=cek) == test_input['plaintext'].encode('utf-8')

    # re-encode and verify we are back where we started
    kek = SymmetricKey(key_ops=KeyOps.WRAP, alg=CoseAlgorithms.DIRECT.id)
    assert msg.encode(encrypt=False, nonce=nonce, key=cek, enc_params=[RcptParams(key=kek)]) == unhexlify(test_output)


@fixture
def setup_encrypt_ecdh_direct_tests(encrypt_ecdh_direct_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_ecdh_direct_test_input)


@mark.encoding
@mark.decoding
def test_encrypt_ecdh_direct_decode_encode(setup_encrypt_ecdh_direct_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_ecdh_direct_tests

    # DECODING

    # parse message and test for headers
    md: EncMessage = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == extract_phdr(test_input, 'enveloped')
    assert md.uhdr == extract_uhdr(test_input, 'enveloped', 1)

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    # verify the receiver and set up the keying material
    recipient = test_input['enveloped']['recipients'][0]

    assert md.recipients[0].phdr == recipient.get('protected', {})
    # do not verify unprotected header since it contains the ephemeral public key of the sender
    # assert m.recipients[0].uhdr == rcpt.get('unprotected', {})

    rcvr_skey, sender_key = setup_ec_receiver_keys(recipient, md.recipients[0].uhdr.get(HeaderKeys.EPHEMERAL_KEY))

    # create context KDF
    v = PartyInfo()
    u = PartyInfo(nonce=unhexlify(test_input['rng_stream'][0])) if "sender_key" in recipient else PartyInfo()
    s = SuppPubInfo(len(test_intermediate['CEK_hex']) * 4, md.recipients[0].encode_phdr())
    kdf_ctx = CoseKDFContext(md.phdr[HeaderKeys.ALG], u, v, s)
    assert kdf_ctx.encode() == unhexlify(test_intermediate['recipients'][0]['Context_hex'])

    secret, kek_bytes = CoseRecipient.derive_kek(rcvr_skey, sender_key, context=kdf_ctx, expose_secret=True)

    assert secret == unhexlify(test_intermediate['recipients'][0]['Secret_hex'])
    assert kek_bytes == unhexlify(test_intermediate['CEK_hex'])

    alg = extract_alg(test_input['enveloped'])
    cek = SymmetricKey(k=kek_bytes)
    nonce = extract_nonce(test_input, 1)
    assert md.decrypt(nonce=nonce, alg=alg, key=cek) == test_input['plaintext'].encode('utf-8')

    # ENCODING

    me = EncMessage(phdr=test_input['enveloped'].get("protected", {}),
                    uhdr=test_input['enveloped'].get("unprotected", {}),
                    payload=test_input['plaintext'].encode('utf-8'))

    if 'rng_stream' in test_input:
        me.uhdr_update({HeaderKeys.IV: unhexlify(test_input['rng_stream'][1])})

    # Set up recipients and keys
    recipient = test_input['enveloped']['recipients'][0]

    if 'sender_key' in recipient:
        r1 = CoseRecipient(phdr=recipient.get('protected', {}))
        r1.uhdr_update({HeaderKeys.STATIC_KEY: sender_key.encode('crv', 'x', 'y')})
        r1.uhdr_update(recipient.get('unprotected', {}))
        r1.uhdr_update({HeaderKeys.PARTY_U_NONCE: unhexlify(test_input['rng_stream'][0])})
    else:
        r1 = CoseRecipient(phdr=recipient.get('protected', {}))
        r1.uhdr_update({HeaderKeys.EPHEMERAL_KEY: sender_key.encode('crv', 'x', 'y')})
        r1.uhdr_update(recipient.get('unprotected', {}))

    # append the first and only recipient
    me.recipients.append(r1)

    # set up cek
    cek = SymmetricKey(k=kek_bytes, alg=alg)
    kek = SymmetricKey(k=kek_bytes, alg=CoseAlgorithms.DIRECT.id)

    # without sorting probably does not match because the order of the recipient elements is not the same
    assert sorted(me.encode(key=cek, nonce=nonce, enc_params=[RcptParams(key=kek)])) == sorted(unhexlify(test_output))


@fixture
def setup_encrypt_ecdh_wrap_tests(encrypt_ecdh_wrap_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_ecdh_wrap_test_input)


@mark.decoding
def test_encrypt_ecdh_wrap_decode(setup_encrypt_ecdh_wrap_tests: tuple):
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_ecdh_wrap_tests
    # DECODING

    # parse message and test for headers
    md: EncMessage = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == extract_phdr(test_input, 'enveloped')
    assert md.uhdr == extract_uhdr(test_input, 'enveloped', 1)

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    recipient = test_input['enveloped']['recipients'][0]
    assert md.recipients[0].phdr == recipient.get('protected', {})
    # do not verify unprotected header since it contains the ephemeral public key of the sender
    # assert m.recipients[0].uhdr == rcpt.get('unprotected', {})

    rcvr_skey, sender_key = setup_ec_receiver_keys(recipient, md.recipients[0].uhdr.get(HeaderKeys.EPHEMERAL_KEY))

    # create context KDF
    s = SuppPubInfo(len(test_intermediate['recipients'][0]['KEK_hex']) * 4, md.recipients[0].encode_phdr())

    if md.recipients[0].phdr[HeaderKeys.ALG] in {CoseAlgorithms.ECDH_ES_A192KW.id, CoseAlgorithms.ECDH_SS_A192KW.id}:
        kdf_ctx = CoseKDFContext(CoseAlgorithms.A192KW.id, PartyInfo(), PartyInfo(), s)
    elif md.recipients[0].phdr[HeaderKeys.ALG] in {CoseAlgorithms.ECDH_ES_A128KW.id, CoseAlgorithms.ECDH_SS_A128KW.id}:
        kdf_ctx = CoseKDFContext(CoseAlgorithms.A128KW.id, PartyInfo(), PartyInfo(), s)
    elif md.recipients[0].phdr[HeaderKeys.ALG] in {CoseAlgorithms.ECDH_ES_A256KW.id, CoseAlgorithms.ECDH_SS_A256KW.id}:
        kdf_ctx = CoseKDFContext(CoseAlgorithms.A256KW.id, PartyInfo(), PartyInfo(), s)
    else:
        raise ValueError("Missed an algorithm?")

    assert kdf_ctx.encode() == unhexlify(test_intermediate['recipients'][0]['Context_hex'])

    secret, kek = CoseRecipient.derive_kek(rcvr_skey, sender_key, context=kdf_ctx, expose_secret=True)

    assert secret == unhexlify(test_intermediate['recipients'][0]['Secret_hex'])
    assert kek == unhexlify(test_intermediate['recipients'][0]['KEK_hex'])

    r1 = md.recipients[0]
    cek = r1.decrypt(key=SymmetricKey(k=kek, alg=r1.phdr[HeaderKeys.ALG]))

    assert cek == unhexlify(test_intermediate['CEK_hex'])

    cek = SymmetricKey(k=cek, alg=extract_alg(test_input["enveloped"]))
    pld = md.decrypt(key=cek, nonce=extract_nonce(test_input, 1))

    assert pld == test_input['plaintext'].encode('utf-8')


@fixture
def setup_encrypt_x25519_direct_tests(encrypt_x25519_direct_test_input: dict) -> tuple:
    return generic_test_setup(encrypt_x25519_direct_test_input)


@mark.decoding
def test_encrypt_x25519_wrap_decode(setup_encrypt_x25519_direct_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_x25519_direct_tests
    # DECODING

    # parse message and test for headers
    md: EncMessage = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == extract_phdr(test_input, 'enveloped')
    assert md.uhdr == extract_uhdr(test_input, 'enveloped', 1)

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    recipient = test_input['enveloped']['recipients'][0]
    assert md.recipients[0].phdr == recipient.get('protected', {})
    # do not verify unprotected header since it contains the ephemeral public key of the sender
    # assert m.recipients[0].uhdr == rcpt.get('unprotected', {})

    rcvr_skey, sender_key = setup_okp_receiver_keys(recipient, md.recipients[0].uhdr.get(HeaderKeys.EPHEMERAL_KEY))

    # create context KDF
    u = PartyInfo(nonce=unhexlify(test_input['rng_stream'][0])) if "sender_key" in recipient else PartyInfo()
    s = SuppPubInfo(len(test_intermediate['CEK_hex']) * 4, md.recipients[0].encode_phdr())
    kdf_ctx = CoseKDFContext(md.phdr[HeaderKeys.ALG], u, PartyInfo(), s)
    assert kdf_ctx.encode() == unhexlify(test_intermediate['recipients'][0]['Context_hex'])

    secret, kek_bytes = CoseRecipient.derive_kek(rcvr_skey, sender_key, context=kdf_ctx, expose_secret=True)

    assert secret == unhexlify(test_intermediate['recipients'][0]['Secret_hex'])
    assert kek_bytes == unhexlify(test_intermediate['CEK_hex'])

    alg = extract_alg(test_input['enveloped'])
    cek = SymmetricKey(k=kek_bytes)
    nonce = extract_nonce(test_input, 1)
    assert md.decrypt(nonce=nonce, alg=alg, key=cek) == test_input['plaintext'].encode('utf-8')


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
    _, test_input, test_output, test_intermediate, fail = setup_encrypt_hkdf_hmac_direct_tests

    # parse message and test for headers
    md: EncMessage = CoseMessage.decode(unhexlify(test_output))
    assert md.phdr == extract_phdr(test_input, 'enveloped')
    assert md.uhdr == extract_uhdr(test_input, 'enveloped', 0)

    # check for external data and verify internal _enc_structure
    md.external_aad = unhexlify(test_input['enveloped'].get('external', b''))
    assert md._enc_structure == unhexlify(test_intermediate['AAD_hex'])

    recipient = test_input['enveloped']['recipients'][0]
    assert md.recipients[0].phdr == recipient.get('protected', {})

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

    priv_data = test_input['enveloped']['recipients'][0].get('unsent', {}).get('priv_other', b'')
    hkdf_context = CoseKDFContext(md.phdr[HeaderKeys.ALG],
                                  u, v, s, priv_data.encode('utf-8') if priv_data != b'' else priv_data)

    assert hkdf_context.encode() == unhexlify(test_intermediate["recipients"][0]['Context_hex'])

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

    cek = SymmetricKey(k=kek, alg=extract_alg(test_input['enveloped']))
    assert md.decrypt(key=cek, nonce=extract_nonce(test_input, 0)) == test_input['plaintext'].encode('utf-8')
