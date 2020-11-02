from binascii import unhexlify

from pytest import mark as m

from cose import OKP
from cose.attributes.algorithms import CoseAlgorithms, CoseEllipticCurves
from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
from cose.keys.cosekey import CoseKey, KTY, KeyOps
from cose.keys.ec2 import EC2
from cose.keys.symmetric import SymmetricKey


@m.parametrize("crv, x, y, expected",
               [
                   (CoseEllipticCurves.P_256,
                    CoseKey.base64decode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
                    CoseKey.base64decode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
                    {1: 2, -1: 1,
                     -2: unhexlify(b'98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
                     -3: unhexlify(b'F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB')}),
                   (CoseEllipticCurves.P_521,
                    CoseKey.base64decode(
                        "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"),
                    CoseKey.base64decode(
                        "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
                    {1: 2, -1: 3,
                     -2: CoseKey.base64decode(
                         "AA4s46qQ+2nkxki6uiGothas9tnyr3aZiI3Y/5pt8WSwWfaEKtJ90k8Yk/rI1cAyg89gIR+dFxOGYtyPFUfCicKl"),
                     -3: CoseKey.base64decode(
                         "AITVahaCQnRaqZ79qdWNRDnuwKaqQ0kYvFSfV/MfOLLAqA/wuHVDZ/MV0b4dgFu5XaOIDgEDXnYOksqFF9MT9ZHu")}),
                   (CoseEllipticCurves.P_256,
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


@m.parametrize('encoded_key_obj',
               [
                   ({-1: 1,
                     -2: unhexlify(b'EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F5'),
                     -3: unhexlify(b'0F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A'),
                     1: 2})
               ], ids=['test_EC2_key_decoding_' + str(i) for i in range(1)])
def test_cosekey_decode(encoded_key_obj):
    key = CoseKey.decode(encoded_key_obj)
    assert type(key) == EC2
    assert key.kty == KTY.EC2
    assert key.crv == CoseEllipticCurves.P_256


@m.parametrize("kid, alg, key_ops, base_iv, k, pl, aad, nonce, algo, ct",
               [("our-secret".encode('utf-8'),
                 CoseAlgorithms.AES_CCM_64_128_256.id,
                 KeyOps.ENCRYPT,
                 b'',
                 unhexlify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
                 "This is the content.".encode("utf-8"),
                 unhexlify("8367456E637279707444A101182140"),
                 unhexlify("89F52F65A1C580"),
                 CoseAlgorithms.AES_CCM_64_128_256.id,
                 unhexlify("721908D60812806F2660054238E931ADB575771EB58752E5F0FB62A828917386A770CE9C")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.AES_CCM_16_64_128.id,
                 KeyOps.ENCRYPT,
                 b'',
                 unhexlify("849B57219DAE48DE646D07DBB533566E"),
                 "This is the content.".encode("utf-8"),
                 unhexlify("8367456E637279707443A1010A40"),
                 unhexlify("89F52F65A1C580933B5261A72F"),
                 CoseAlgorithms.AES_CCM_16_64_128.id,
                 unhexlify("6899DA0A132BD2D2B9B10915743EE1F7B92A46802388816C040275EE")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.AES_CCM_16_64_256.id,
                 KeyOps.ENCRYPT,
                 b'',
                 unhexlify("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100"),
                 "This is the content.".encode("utf-8"),
                 unhexlify("8367456E637279707443A1010B40"),
                 unhexlify("89F52F65A1C580933B5261A72F"),
                 CoseAlgorithms.AES_CCM_16_64_256.id,
                 unhexlify("28B3BDDFF844A736C5F0EE0F8C691FD0B7ADF917A8A3EF3313D6D332")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.A128GCM.id,
                 KeyOps.ENCRYPT,
                 b'',
                 unhexlify("849B57219DAE48DE646D07DBB533566E"),
                 "This is the content.".encode("utf-8"),
                 unhexlify("8367456E637279707443A1010140"),
                 unhexlify("02D1F7E6F26C43D4868D87CE"),
                 CoseAlgorithms.A128GCM.id,
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


@m.parametrize("kid, alg, key_ops, base_iv, k, pl, algo, ct",
               [("our-secret".encode('utf-8'),
                 CoseAlgorithms.A128KW.id,
                 KeyOps.WRAP,
                 b'',
                 CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbg"),
                 unhexlify("DDDC08972DF9BE62855291A17A1B4CF7"),
                 CoseAlgorithms.A128KW.id,
                 unhexlify("2F8A3D2AA397D3D5C40AAF9F6656BAFA5DB714EF925B72BC")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.A192KW.id,
                 KeyOps.WRAP,
                 b'',
                 CoseKey.base64decode("Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmI"),
                 unhexlify("7A1B4CF77102CE028A0308C11D50A36F"),
                 CoseAlgorithms.A192KW.id,
                 unhexlify("4677A7C41F33EC27E8489AFBA06249A649F01F06496DC414"))
                ], ids=["Key_wrap_AES_KW_128", "Key_wrap_AES_KW_192"])
def test_symmetric_key_wrap(kid, alg, key_ops, base_iv, k, pl, algo, ct):
    key = SymmetricKey(kid=kid, alg=alg, key_ops=key_ops, base_iv=base_iv, k=k)

    assert ct == key.key_wrap(pl, algo)

    # switch to another key operation
    key.key_ops = KeyOps.UNWRAP
    assert pl == key.key_unwrap(ct, algo)


@m.parametrize("kid, alg, key_ops, base_iv, k, pl, algo, ct",
               [("our-secret".encode('utf-8'),
                 CoseAlgorithms.HMAC_256_256,
                 KeyOps.MAC_CREATE,
                 b'',
                 unhexlify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
                 unhexlify("84634D4143404054546869732069732074686520636F6E74656E742E"),
                 CoseAlgorithms.HMAC_256_256,
                 unhexlify("C2EBE664C1D996AA3026824BBBB7CAA454E2CC4212181AD9F34C7879CBA1972E")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.HMAC_256_256,
                 KeyOps.MAC_CREATE,
                 b'',
                 unhexlify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
                 unhexlify("84634D414343A101054054546869732069732074686520636F6E74656E742E"),
                 CoseAlgorithms.HMAC_256_256,
                 unhexlify("2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.AES_MAC_128_128,
                 KeyOps.MAC_CREATE,
                 b'',
                 unhexlify("849B57219DAE48DE646D07DBB533566E"),
                 unhexlify("84634D414344A10118194054546869732069732074686520636F6E74656E742E"),
                 CoseAlgorithms.AES_MAC_128_128,
                 unhexlify("B242D2A935FEB4D66FF8334AC95BF72B")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.AES_MAC_128_64,
                 KeyOps.MAC_CREATE,
                 b'',
                 unhexlify("849B57219DAE48DE646D07DBB533566E"),
                 unhexlify("84634D414343A1010E4054546869732069732074686520636F6E74656E742E"),
                 CoseAlgorithms.AES_MAC_128_64,
                 unhexlify("C1CA820E6E247089")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.AES_MAC_256_64,
                 KeyOps.MAC_CREATE,
                 b'',
                 unhexlify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
                 unhexlify("84644D41433043A1010F4054546869732069732074686520636F6E74656E742E"),
                 CoseAlgorithms.AES_MAC_256_64,
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


@m.parametrize("kid, alg, key_ops, base_iv, k, salt, algo, ctx_alg, u, v, pub, priv, context, cek",
               [("our-secret".encode('utf-8'),
                 CoseAlgorithms.DIRECT_HKDF_SHA_256,
                 KeyOps.DERIVE_KEY,
                 b'',
                 CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
                 "aabbccddeeffgghh".encode("utf-8"),
                 CoseAlgorithms.DIRECT_HKDF_SHA_256,
                 CoseAlgorithms.AES_CCM_16_64_128,
                 PartyInfo(),
                 PartyInfo(),
                 SuppPubInfo(128, b'\xa1\x01)'),
                 b"",
                 unhexlify("840A83F6F6F683F6F6F682188043A10129"),
                 unhexlify("32547753D1E24F41579D770BA852D4C9")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.DIRECT_HKDF_SHA_256,
                 KeyOps.DERIVE_KEY,
                 b'',
                 CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
                 b'',
                 CoseAlgorithms.DIRECT_HKDF_SHA_256,
                 CoseAlgorithms.AES_CCM_16_64_128,
                 PartyInfo(nonce=b"S101", identity=b"Sender"),
                 PartyInfo(nonce=b"R102", identity=b"Recipient"),
                 SuppPubInfo(128, b'\xa1\x01)'),
                 b"",
                 unhexlify("840A834653656E6465724453313031F68349526563697069656E744452313032F682188043A10129"),
                 unhexlify("052B7540EEE119A13779C16AF4520012")),
                ("our-secret".encode('utf-8'),
                 CoseAlgorithms.DIRECT_HKDF_SHA_512,
                 KeyOps.DERIVE_KEY,
                 b'',
                 CoseKey.base64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
                 b'',
                 CoseAlgorithms.DIRECT_HKDF_SHA_512,
                 CoseAlgorithms.AES_CCM_16_64_128,
                 PartyInfo(nonce=b"S101", identity=b"Sender", other=b"S-other"),
                 PartyInfo(nonce=b"R102", identity=b"Recipient", other=b"R-other"),
                 SuppPubInfo(128, b'\xa1\x01*'),
                 b"",
                 CoseKey.base64decode("hAqDRlNlbmRlckRTMTAxR1Mtb3RoZXKDSVJlY2lwaWVudERSMTAyR1Itb3RoZXKCGIBDoQEq"),
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


ctx_1 = "hAeD9lhAAtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cPJz03y/" \
        "mxjK/eIZBP3bohS2NMJednAIXpCSUG1ygKjqvaD9vb2ghkCAEShATgb"

ctx_2 = "hAeD9lhAAtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cPJz03y/" \
        "mxjK/eIZBP3bohSwncr+1cLLRHSzTxbaIiv7/aD9vb2ghkCAEShATgb"


@m.parametrize("kid, alg, key_ops, x, y, d, curve, pub_x, pub_y, ctx_alg, u, v, pub, priv, ctx, cek",
               [(b"meriadoc.brandybuck@buckland.example",
                 CoseAlgorithms.ECDH_ES_HKDF_256,
                 KeyOps.DERIVE_KEY,
                 CoseKey.base64decode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
                 CoseKey.base64decode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
                 CoseKey.base64decode("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"),
                 CoseEllipticCurves.P_256,
                 unhexlify("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280"),
                 unhexlify("F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB"),
                 CoseAlgorithms.A128GCM,
                 PartyInfo(),
                 PartyInfo(),
                 SuppPubInfo(128, unhexlify(b"A1013818")),
                 b"",
                 unhexlify("840183F6F6F683F6F6F682188044A1013818"),
                 unhexlify("56074D506729CA40C4B4FE50C6439893")),

                (b"meriadoc.brandybuck@buckland.example",
                 CoseAlgorithms.ECDH_SS_HKDF_512,
                 KeyOps.DERIVE_KEY,
                 CoseKey.base64decode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
                 CoseKey.base64decode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
                 CoseKey.base64decode("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"),
                 CoseEllipticCurves.P_256,
                 CoseKey.base64decode("7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU"),
                 CoseKey.base64decode("DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo"),
                 CoseAlgorithms.HMAC_512_512,
                 PartyInfo(nonce=CoseKey.base64decode(
                     "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cPJz03y/mxjK/eIZBP3bohS2NMJednAIXpCSUG1ygKjqg==")),
                 PartyInfo(),
                 SuppPubInfo(512, unhexlify("A101381B")),
                 b"",
                 CoseKey.base64decode(ctx_1),
                 CoseKey.base64decode(
                     "r7rA5gV0NKGbm0l6M2Sh6RSQ3RBRhvvg15gkle/0GmD3s+YJkJo/3bjlyqX+/GOB+x+8snoGoQz6ToffsMPP/A==")),

                (b"meriadoc.brandybuck@buckland.example",
                 CoseAlgorithms.ECDH_SS_HKDF_512,
                 KeyOps.DERIVE_KEY,
                 CoseKey.base64decode(
                     "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"),
                 CoseKey.base64decode(
                     "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
                 CoseKey.base64decode(
                     "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"),
                 CoseEllipticCurves.P_521,
                 CoseKey.base64decode(
                     "APP1tIC1Ey2__4aekg06nicpK3uvQELX7HPaZUXYf2qd-YCYZlR7L6RqW0CiGjNv9uyJ5srxdRb_St87pwbfZx4B"),
                 CoseKey.base64decode(
                     "AQMe7-xEu5s49sLiFXIGsY4FVgAxFe6HW1nT3sqOcqgkFs0_Y7fWpDkAGLc1Og3Qqmt7-8-7d0fTW1nNtf5RJqdM"),
                 CoseAlgorithms.HMAC_512_512,
                 PartyInfo(nonce=CoseKey.base64decode(
                     "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cPJz03y/mxjK/eIZBP3bohSwncr+1cLLRHSzTxbaIiv7w==")),
                 PartyInfo(),
                 SuppPubInfo(512, unhexlify("A101381B")),
                 b"",
                 CoseKey.base64decode(ctx_2),
                 CoseKey.base64decode(
                     "3N8VPRYAS1E9VVowWFVhKz0ETwqvZpJzyvo9UijAoSriZnomNlaCa2MTmJWLGMG6NmDWzfFT1goIizCJqayCLA=="))
                ], ids=["Key_derivation_ECDH_P256_HDKF_SHA_256",
                        "Key_derivation_ECDH_P256_HKDF_SHA_512",
                        "Key_derivation_ECDH_P521_HKDF_SHA_512"])
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


@m.parametrize("kid, alg, key_ops, x, y, d, curve, to_sign, signature",
               [(b"11",
                 CoseAlgorithms.ES256,
                 KeyOps.SIGN,
                 CoseKey.base64decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
                 CoseKey.base64decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
                 CoseKey.base64decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
                 CoseEllipticCurves.P_256,
                 unhexlify("85695369676E617475726543A1030043A101264054546869732069732074686520636F6E74656E742E"),
                 CoseKey.base64decode(
                     "1xwF21LJzn8b9arAEzS76srB2GojA+buqokmb0XAHtYCymSer3kNi8mdJFhFfKaocgYZQOevvkjiid+sFGriWA==")),
                # (b"bilbo.baggins@hobbiton.example",
                #  CoseAlgorithms.ES512,
                #  KeyOps.SIGN,
                #  CoseKey.base64decode(
                #      "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"),
                #  CoseKey.base64decode(
                #      "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
                #  CoseKey.base64decode(
                #      "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"),
                #  CoseEllipticCurves.P_521,
                #  unhexlify("846A5369676E61747572653144A10138234054546869732069732074686520636F6E74656E742E"),
                #  unhexlify("01664DD6962091B5100D6E1833D503539330EC2BC8FD3E8996950CE9F70259D9A30F73794F603B0D3E7C5E9C4C2A57E10211F76E79DF8FFD1B79D7EF5B9FA7DA109001965FA2D37E093BB13C040399C467B3B9908C09DB2B0F1F4996FE07BB02AAA121A8E1C671F3F997ADE7D651081017057BD3A8A5FBF394972EA71CFDC15E6F8FE2E1"))
                ])
def test_ec_ecdsa(kid, alg, key_ops, x, y, d, curve, to_sign, signature):
    key = EC2(
        kid=kid,
        alg=alg,
        key_ops=key_ops,
        x=x,
        y=y,
        d=d,
        crv=curve
    )

    assert key.sign(to_be_signed=to_sign, alg=alg, curve=curve) == signature

    # switch key operation
    key.key_ops = KeyOps.VERIFY
    assert key.verify(to_be_signed=to_sign, signature=signature, alg=alg, curve=curve)


def test_ec2_key_generation():
    key = EC2.generate_key(CoseAlgorithms.ES256, KeyOps.SIGN, CoseEllipticCurves.P_256)
    assert isinstance(key, EC2)


def test_okp_key_generation():
    key = OKP.generate_key(CoseAlgorithms.EDDSA, KeyOps.SIGN, CoseEllipticCurves.X25519)
    assert isinstance(key, OKP)


def test_symmetric_key_generation():
    key = SymmetricKey.generate_key(CoseAlgorithms.A128GCM, KeyOps.ENCRYPT, 16)
    assert isinstance(key, SymmetricKey)
