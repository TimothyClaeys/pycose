from binascii import unhexlify

from pytest import mark

from pycose.algorithms import AlgorithmIDs
from pycose.context import CoseKDFContext, PartyInfo, SuppPubInfo
from pycose.keys.cosekey import EllipticCurveTypes, CoseKey, KTY, KeyOps
from pycose.keys.ec import EC2
from pycose.keys.symmetric import SymmetricKey


@mark.parametrize("crv, x, y, expected",
                  [
                      (EllipticCurveTypes.P_256,
                       CoseKey.base64decode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
                       CoseKey.base64decode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
                       {1: 2, -1: 1,
                        -2: unhexlify(b'98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
                        -3: unhexlify(b'F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB')}),
                      (EllipticCurveTypes.P_521,
                       CoseKey.base64decode(
                           "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"),
                       CoseKey.base64decode(
                           "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
                       {1: 2, -1: 3,
                        -2: unhexlify(
                            b'000E2CE3AA90FB69E4C648BABA21A8B616ACF6D9F2AF7699888DD8FF9A6DF164B059F6842AD27DD24F1893FAC8D5C03283CF60211F9D17138662DC8F1547C289C2A5'),
                        -3: unhexlify(
                            b'0084D56A168242745AA99EFDA9D58D4439EEC0A6AA434918BC549F57F31F38B2C0A80FF0B8754367F315D1BE1D805BB95DA3880E01035E760E92CA8517D313F591EE')}),
                      (EllipticCurveTypes.P_256,
                       CoseKey.base64decode("7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU"),
                       CoseKey.base64decode("DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo"),
                       {-1: 1,
                        -2: unhexlify(b'EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F5'),
                        -3: unhexlify(b'0F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A'),
                        1: 2}
                       )
                  ], ids=['test_EC2_key_encoding_' + str(i) for i in range(3)])
def test_cosekey_create(crv, x, y, expected):
    key = EC2(crv=crv, x=x, y=y)
    assert sorted(key.encode('x', 'y', 'crv')) == sorted(expected)


@mark.parametrize('encoded_key_obj, expected',
                  [
                      ({-1: 1,
                        -2: unhexlify(b'EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F5'),
                        -3: unhexlify(b'0F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A'),
                        1: 2},
                       {CoseKey.Common.KTY: KTY.EC2,
                        EC2.EC2Prm.CRV: EllipticCurveTypes.P_256,
                        EC2.EC2Prm.X: unhexlify(
                            b'edcbd809c754db6582c16d6d65747c8aecc92d619c778eb17f13b55c9b3e48f5'),
                        EC2.EC2Prm.Y: unhexlify(
                            b'0f38495e0cfd448e93b1e366c047cba0d567b3c526bce36c3f3403a29d9d2a8a')}
                       )], ids=['test_EC2_key_decoding_' + str(i) for i in range(1)])
def test_cosekey_decode(encoded_key_obj, expected):
    key = CoseKey.decode(encoded_key_obj)
    assert key == expected


@mark.parametrize("kid, alg, key_ops, base_iv, k, pl, aad, nonce, algo, ct",
                  [("our-secret".encode('utf-8'),
                    AlgorithmIDs.AES_CCM_64_128_256,
                    KeyOps.ENCRYPT,
                    b'',
                    unhexlify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
                    "This is the content.".encode("utf-8"),
                    unhexlify("8367456E637279707444A101182140"),
                    unhexlify("89F52F65A1C580"),
                    AlgorithmIDs.AES_CCM_64_128_256,
                    unhexlify("721908D60812806F2660054238E931ADB575771EB58752E5F0FB62A828917386A770CE9C")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.AES_CCM_16_64_128,
                    KeyOps.ENCRYPT,
                    b'',
                    unhexlify("849B57219DAE48DE646D07DBB533566E"),
                    "This is the content.".encode("utf-8"),
                    unhexlify("8367456E637279707443A1010A40"),
                    unhexlify("89F52F65A1C580933B5261A72F"),
                    AlgorithmIDs.AES_CCM_16_64_128,
                    unhexlify("6899DA0A132BD2D2B9B10915743EE1F7B92A46802388816C040275EE")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.AES_CCM_16_64_256,
                    KeyOps.ENCRYPT,
                    b'',
                    unhexlify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
                    "This is the content.".encode("utf-8"),
                    unhexlify("8367456E637279707443A1010B40"),
                    unhexlify("89F52F65A1C580933B5261A72F"),
                    AlgorithmIDs.AES_CCM_16_64_256,
                    unhexlify("28B3BDDFF844A736C5F0EE0F8C691FD0B7ADF917A8A3EF3313D6D332")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.A128GCM,
                    KeyOps.ENCRYPT,
                    b'',
                    unhexlify("849B57219DAE48DE646D07DBB533566E"),
                    "This is the content.".encode("utf-8"),
                    unhexlify("8367456E637279707443A1010140"),
                    unhexlify("02D1F7E6F26C43D4868D87CE"),
                    AlgorithmIDs.A128GCM,
                    unhexlify("60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC")),
                   ], ids=["Encrypt_AES_CCM_64_128_256", "Encrypt_AES_CCM_16_64_128", "Encrypt_AES_CCM_16_64_256",
                           "Encrypt_AES_GCM_128"])
def test_symmetric_key_aeads(kid, alg, key_ops, base_iv, k, pl, aad, nonce, algo, ct):
    key = SymmetricKey(
        kid=kid,
        alg=alg,
        key_ops=key_ops,
        base_iv=base_iv,
        k=k
    )

    assert ct == key.encrypt(pl, aad, nonce, algo)

    # switch to another key operation
    key.key_ops = KeyOps.DECRYPT
    assert pl == key.decrypt(ct, aad, nonce, algo)


@mark.parametrize("kid, alg, key_ops, base_iv, k, pl, algo, ct",
                  [("our-secret".encode('utf-8'),
                    AlgorithmIDs.A128KW,
                    KeyOps.WRAP,
                    b'',
                    CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbg"),
                    unhexlify("DDDC08972DF9BE62855291A17A1B4CF7"),
                    AlgorithmIDs.A128KW,
                    unhexlify("2F8A3D2AA397D3D5C40AAF9F6656BAFA5DB714EF925B72BC")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.A192KW,
                    KeyOps.WRAP,
                    b'',
                    CoseKey.base64decode("Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmI"),
                    unhexlify("7A1B4CF77102CE028A0308C11D50A36F"),
                    AlgorithmIDs.A192KW,
                    unhexlify("4677A7C41F33EC27E8489AFBA06249A649F01F06496DC414"))
                   ], ids=["Key_wrap_AES_KW_128", "Key_wrap_AES_KW_192"])
def test_symmetric_key_wrap(kid, alg, key_ops, base_iv, k, pl, algo, ct):
    key = SymmetricKey(
        kid=kid,
        alg=alg,
        key_ops=key_ops,
        base_iv=base_iv,
        k=k
    )

    assert ct == key.key_wrap(pl, algo)

    # switch to another key operation
    key.key_ops = KeyOps.UNWRAP
    assert pl == key.key_unwrap(ct, algo)


@mark.parametrize("kid, alg, key_ops, base_iv, k, pl, algo, ct",
                  [("our-secret".encode('utf-8'),
                    AlgorithmIDs.HMAC_256_256,
                    KeyOps.MAC_CREATE,
                    b'',
                    unhexlify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
                    unhexlify("84634D4143404054546869732069732074686520636F6E74656E742E"),
                    AlgorithmIDs.HMAC_256_256,
                    unhexlify("C2EBE664C1D996AA3026824BBBB7CAA454E2CC4212181AD9F34C7879CBA1972E")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.HMAC_256_256,
                    KeyOps.MAC_CREATE,
                    b'',
                    unhexlify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
                    unhexlify("84634D414343A101054054546869732069732074686520636F6E74656E742E"),
                    AlgorithmIDs.HMAC_256_256,
                    unhexlify("2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.AES_MAC_128_128,
                    KeyOps.MAC_CREATE,
                    b'',
                    unhexlify("849B57219DAE48DE646D07DBB533566E"),
                    unhexlify("84634D414344A10118194054546869732069732074686520636F6E74656E742E"),
                    AlgorithmIDs.AES_MAC_128_128,
                    unhexlify("B242D2A935FEB4D66FF8334AC95BF72B")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.AES_MAC_128_64,
                    KeyOps.MAC_CREATE,
                    b'',
                    unhexlify("849B57219DAE48DE646D07DBB533566E"),
                    unhexlify("84634D414343A1010E4054546869732069732074686520636F6E74656E742E"),
                    AlgorithmIDs.AES_MAC_128_64,
                    unhexlify("C1CA820E6E247089")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.AES_MAC_256_64,
                    KeyOps.MAC_CREATE,
                    b'',
                    unhexlify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
                    unhexlify("84644D41433043A1010F4054546869732069732074686520636F6E74656E742E"),
                    AlgorithmIDs.AES_MAC_256_64,
                    unhexlify("726043745027214F")),
                   ], ids=["MAC_HMAC_256_0", "MAC_HMAC_256_1", "MAC_AES_CBC_128_128", "MAC_AES_CBC_128_64",
                           "MAC_AES_CBC_256_64"])
def test_symmetric_mac(kid, alg, key_ops, base_iv, k, pl, algo, ct):
    key = SymmetricKey(
        kid=kid,
        alg=alg,
        key_ops=key_ops,
        base_iv=base_iv,
        k=k
    )

    assert ct == key.compute_tag(pl, algo)

    # switch to another key operation
    key.key_ops = KeyOps.MAC_VERIFY
    assert key.verify_tag(ct, pl, algo)


@mark.parametrize("kid, alg, key_ops, base_iv, k, salt, algo, ctx_alg, u, v, pub, priv, context, cek",
                  [("our-secret".encode('utf-8'),
                    AlgorithmIDs.DIRECT_HKDF_SHA_256,
                    KeyOps.DERIVE_KEY,
                    b'',
                    CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
                    "aabbccddeeffgghh".encode("utf-8"),
                    AlgorithmIDs.DIRECT_HKDF_SHA_256,
                    AlgorithmIDs.AES_CCM_16_64_128,
                    PartyInfo(),
                    PartyInfo(),
                    SuppPubInfo(128, b'\xa1\x01)'),
                    b"",
                    unhexlify("840A83F6F6F683F6F6F682188043A10129"),
                    unhexlify("32547753D1E24F41579D770BA852D4C9")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.DIRECT_HKDF_SHA_256,
                    KeyOps.DERIVE_KEY,
                    b'',
                    CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
                    b'',
                    AlgorithmIDs.DIRECT_HKDF_SHA_256,
                    AlgorithmIDs.AES_CCM_16_64_128,
                    PartyInfo(nonce=b"S101", identity=b"Sender"),
                    PartyInfo(nonce=b"R102", identity=b"Recipient"),
                    SuppPubInfo(128, b'\xa1\x01)'),
                    b"",
                    unhexlify("840A834653656E6465724453313031F68349526563697069656E744452313032F682188043A10129"),
                    unhexlify("052B7540EEE119A13779C16AF4520012")),
                   ("our-secret".encode('utf-8'),
                    AlgorithmIDs.DIRECT_HKDF_SHA_512,
                    KeyOps.DERIVE_KEY,
                    b'',
                    CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
                    b'',
                    AlgorithmIDs.DIRECT_HKDF_SHA_512,
                    AlgorithmIDs.AES_CCM_16_64_128,
                    PartyInfo(nonce=b"S101", identity=b"Sender", other=b"S-other"),
                    PartyInfo(nonce=b"R102", identity=b"Recipient", other=b"R-other"),
                    SuppPubInfo(128, b'\xa1\x01*'),
                    b"",
                    unhexlify(
                        "840A834653656E646572445331303147532D6F746865728349526563697069656E74445231303247522D6F7468657282188043A1012A"),
                    unhexlify("01F08D7721A32295D95B97B1684648E4"))
                   ], ids=["Key_derivation_HKDF_HMAC_SHA256_0", "Key_derivation_HKDF_HMAC_SHA256_1",
                           "Key_derivation_HKDF_HMAC_SHA512"])
def test_symmetric_key_derivation(kid, alg, key_ops, base_iv, k, salt, algo, ctx_alg, u, v, pub, priv, context, cek):
    key = SymmetricKey(
        kid=kid,
        alg=alg,
        key_ops=key_ops,
        base_iv=base_iv,
        k=k
    )

    ctx = CoseKDFContext(ctx_alg, u, v, pub, priv)
    assert ctx.encode() == context

    assert key.hmac_key_derivation(ctx, algo, salt) == cek


@mark.parametrize("kid, alg, key_ops, x, y, d, curve, pub_x, pub_y, ctx_alg, u, v, pub, priv, ctx, cek",
                  [(b"meriadoc.brandybuck@buckland.example",
                    AlgorithmIDs.ECDH_ES_HKDF_256,
                    KeyOps.DERIVE_KEY,
                    CoseKey.base64decode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
                    CoseKey.base64decode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
                    CoseKey.base64decode("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"),
                    EllipticCurveTypes.P_256,
                    unhexlify("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280"),
                    unhexlify("F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB"),
                    AlgorithmIDs.A128GCM,
                    PartyInfo(),
                    PartyInfo(),
                    SuppPubInfo(128, unhexlify(b"A1013818")),
                    b"",
                    unhexlify("840183F6F6F683F6F6F682188044A1013818"),
                    unhexlify("56074D506729CA40C4B4FE50C6439893"))
                   ], ids=["Key_derivation_ECDH_P256_HDKF_SHA_256"])
def test_ec_ecdh_key_derivation(kid, alg, key_ops, x, y, d, curve, pub_x, pub_y, ctx_alg, u, v, pub, priv, ctx, cek):
    key = EC2(
        kid=kid,
        alg=alg,
        key_ops=key_ops,
        x=x,
        y=y,
        d=d,
        crv=curve
    )

    kdf_ctx = CoseKDFContext(ctx_alg, u, v, pub, priv)
    assert ctx == kdf_ctx.encode()

    pub_key = EC2(
        alg=alg,
        key_ops=key_ops,
        x=pub_x,
        y=pub_y,
        crv=curve
    )

    _, kek = key.ecdh_key_derivation(pub_key, kdf_ctx, alg, curve)
    assert kek == cek
