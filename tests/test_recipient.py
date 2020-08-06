from binascii import unhexlify

from pytest import mark

from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.cosekey import CoseKey, EC2, CoseEllipticCurves, EcdhAlgorithmParam
from pycose.crypto import CoseKDFContext, PartyInfo, SuppPubInfo
from pycose.recipients import CoseRecipient


@mark.parametrize("phdr, uhdr, alg, peer_key, private_key, encoded_phdr, encoded_uhdr, cek",
                  [
                      ({CoseHeaderParam.ALG: CoseAlgorithm.ECDH_ES_HKDF_256},
                       {
                           EcdhAlgorithmParam.EPHEMERAL_KEY:
                               EC2(crv=CoseEllipticCurves.P_256,
                                   x=CoseKey.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                                   y=CoseKey.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw')).encode(),
                           CoseHeaderParam.KID: "meriadoc.brandybuck@buckland.example".encode('utf-8')
                       },
                       CoseAlgorithm.A128GCM,
                       EC2(crv=CoseEllipticCurves.P_256,
                           x=CoseKey.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                           y=CoseKey.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw')),
                       EC2(crv=CoseEllipticCurves.P_256,
                           d=unhexlify(b'02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3')),
                       unhexlify(b'A1013818'),
                       {-1: {1: 2, -1: 1,
                             -2: unhexlify(b'98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
                             -3: unhexlify(b'F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB')},
                        4: unhexlify(b'6D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65')},
                       unhexlify(b'56074D506729CA40C4B4FE50C6439893')
                       )
                  ])
def test_kek_direct_recipient(phdr, uhdr, alg, peer_key, private_key, encoded_phdr, encoded_uhdr, cek):
    r = CoseRecipient(phdr=phdr, uhdr=uhdr)

    u = PartyInfo()
    v = PartyInfo()
    s = SuppPubInfo(128, r.encode_phdr())
    kdf_ctx = CoseKDFContext(alg, u, v, s)
    kek = r.derive_kek(private_key=private_key, public_key=peer_key, context=kdf_ctx)

    # since this is direct usage --> kek == cek
    assert kek == cek

    assert r.encode_phdr() == encoded_phdr
    assert r.encode_uhdr() == encoded_uhdr

    # no encryption of cek required since the key is used directly
    # r.encrypt()

    # assert r.payload == unhexlify(wrapped_key)
    # assert hexlify(r.encode()) == hexlify(cbor2.dumps(expected))

# @pytest.mark.parametrize("phdr, uhdr, d1, crv, d_hex, payload, cek, alg, nonce, d2, secret, context, phdr_res",
#                          [
#                              ({CoseHeaderParam.ALG: CoseAlgorithm.ECDH_ES_HKDF_256},
#                               {CoseHeaderParam.KID: "meriadoc.brandybuck@buckland.example".encode('utf-8')},
#                               int(hexlify(CoseKey.base64decode("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8")), 16),
#                               SECP256R1,
#                               'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf',
#                               b'This is the content',
#                               unhexlify(b'56074D506729CA40C4B4FE50C6439893'),
#                               CoseAlgorithm.A128GCM,
#                               unhexlify(b'C9CF4DF2FE6C632BF7886413'),
#                               int("02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3", 16),
#                               b'4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
#                               unhexlify(b'840183F6F6F683F6F6F682188044A1013818'),
#                               unhexlify(b'A1013818'))
#                          ])
# def test_key_derivation_direct_recipient(phdr: dict,
#                                          uhdr: dict,
#                                          d1: int,
#                                          crv: Type[EllipticCurve],
#                                          d_hex: str,
#                                          payload: bytes,
#                                          cek: bytes,
#                                          alg: int,
#                                          nonce: bytes,
#                                          d2: int,
#                                          secret: bytes,
#                                          context: bytes,
#                                          phdr_res: bytes):
#     d1 = derive_private_key(d1, crv(), openssl.backend)
#     private_numbers = d1.private_numbers()
#
#     assert hex(private_numbers.private_value) == hex(int(d_hex, 16))
#
#     m = Enc0Message(payload=payload)
#     m.key = cek
#     m.encrypt(alg=alg, nonce=nonce)
#
#     d2 = derive_private_key(d2, crv(), openssl.backend)
#
#     r = CoseRecipient(phdr=phdr, uhdr=uhdr)
#
#     assert r.encode_phdr() == phdr_res
#     kdf_ctx = CoseKDFContext(CoseAlgorithm.A128GCM, PartyInfo(), PartyInfo(), SuppPubInfo(128, r.encode_phdr()))
#
#     assert kdf_ctx.encode() == context
#
#     shared_secret, derived_key = ecdh_key_derivation(d1, d2.public_key(), 16, context)
#     assert derived_key == cek
#     assert shared_secret == unhexlify(secret)
#
