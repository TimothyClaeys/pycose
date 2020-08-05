from binascii import unhexlify, hexlify
from typing import Type

import cbor2
import pytest
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256R1, EllipticCurve

from pycose import Enc0Message
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
from pycose.crypto import ecdh_key_derivation, CoseKDFContext, PartyInfo, SuppPubInfo
from pycose.recipients import CoseRecipient
from tests.conftest import base64decode


@pytest.mark.parametrize("phdr, uhdr, cek, kek, encoded_phdr, encoded_uhdr, wrapped_key, expected",
                         [
                             ({}, {CoseHeaderParam.ALG: CoseAlgorithm.A128KW,
                                   CoseHeaderParam.KID: "our-secret".encode('utf-8')},
                              b'DDDC08972DF9BE62855291A17A1B4CF7',
                              'hJtXIZ2uSN5kbQfbtTNWbg',
                              b'',
                              {1: -3, 4: unhexlify(b'6F75722D736563726574')},
                              b'2F8A3D2AA397D3D5C40AAF9F6656BAFA5DB714EF925B72BC',
                              [b'', {1: -3, 4: unhexlify(b'6F75722D736563726574')},
                               unhexlify(b'2F8A3D2AA397D3D5C40AAF9F6656BAFA5DB714EF925B72BC')]),

                             ({}, {CoseHeaderParam.ALG: CoseAlgorithm.A256KW,
                                   CoseHeaderParam.KID: "018c0ae5-4d9b-471b-bfd6-eef314bc7037".encode('utf-8')},
                              b'DDDC08972DF9BE62855291A17A1B4CF7EA02A160193C28DD5088A862996DE2502C6C499BE6211E5CCEF2F21EF0F8DF69C5BE05EC8F1179D216F06D3155EC127E',
                              "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
                              b'',
                              {1: -5, 4: unhexlify(
                                  b'30313863306165352D346439622D343731622D626664362D656566333134626337303337')},
                              b'3FBB60F882C1523A8B7768CA0C48920425A3CC47935F0D7FD4980020E378EAB85210D97B557B891EEC70785DB812C57DF719F064540ED84D5C93C8765095E422DDBCEF290D86633D',
                              [b'', {
                                  1: -5,
                                  4: unhexlify(
                                      b'30313863306165352D346439622D343731622D626664362D656566333134626337303337')
                              },
                               unhexlify(
                                   b'3FBB60F882C1523A8B7768CA0C48920425A3CC47935F0D7FD4980020E378EAB85210D97B557B891EEC70785DB812C57DF719F064540ED84D5C93C8765095E422DDBCEF290D86633D')])
                         ])
def test_key_wrap_recipient(phdr, uhdr, cek, kek, encoded_phdr, encoded_uhdr, wrapped_key, expected):
    r = CoseRecipient(phdr=phdr, uhdr=uhdr, payload=unhexlify(cek))
    r.wrapping_key = base64decode(kek)

    assert r.encode_phdr() == unhexlify(encoded_phdr)
    assert r.encode_uhdr() == encoded_uhdr

    r.encrypt()

    assert r.payload == unhexlify(wrapped_key)
    assert hexlify(r.encode()) == hexlify(cbor2.dumps(expected))


@pytest.mark.parametrize("phdr, uhdr, d1, crv, d_hex, payload, cek, alg, nonce, d2, secret, context, phdr_res",
                         [
                             ({CoseHeaderParam.ALG: CoseAlgorithm.ECDH_ES_HKDF_256},
                              {CoseHeaderParam.KID: "meriadoc.brandybuck@buckland.example".encode('utf-8')},
                              int(hexlify(base64decode("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8")), 16),
                              SECP256R1,
                              'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf',
                              b'This is the content',
                              unhexlify(b'56074D506729CA40C4B4FE50C6439893'),
                              CoseAlgorithm.A128GCM,
                              unhexlify(b'C9CF4DF2FE6C632BF7886413'),
                              int("02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3", 16),
                              b'4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
                              unhexlify(b'840183F6F6F683F6F6F682188044A1013818'),
                              unhexlify(b'A1013818'))
                         ])
def test_key_derivation_direct_recipient(phdr: dict,
                                         uhdr: dict,
                                         d1: int,
                                         crv: Type[EllipticCurve],
                                         d_hex: str,
                                         payload: bytes,
                                         cek: bytes,
                                         alg: int,
                                         nonce: bytes,
                                         d2: int,
                                         secret: bytes,
                                         context: bytes,
                                         phdr_res: bytes):
    d1 = derive_private_key(d1, crv(), openssl.backend)
    private_numbers = d1.private_numbers()

    assert hex(private_numbers.private_value) == hex(int(d_hex, 16))

    m = Enc0Message(payload=payload)
    m.key = cek
    m.encrypt(alg=alg, nonce=nonce)

    d2 = derive_private_key(d2, crv(), openssl.backend)

    r = CoseRecipient(phdr=phdr, uhdr=uhdr)

    assert r.encode_phdr() == phdr_res
    kdf_ctx = CoseKDFContext(CoseAlgorithm.A128GCM, PartyInfo(), PartyInfo(), SuppPubInfo(128, r.encode_phdr()))

    assert kdf_ctx.encode() == context

    shared_secret, derived_key = ecdh_key_derivation(d1, d2.public_key(), 16, context)
    assert derived_key == cek
    assert shared_secret == unhexlify(secret)

