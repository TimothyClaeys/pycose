from binascii import unhexlify, hexlify

import cbor2
import pytest
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256R1, ECDH
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pycose import Enc0Message
from pycose.attributes import CoseHeaderParam, CoseAlgorithm
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
    r.key = base64decode(kek)

    assert r.encode_phdr() == unhexlify(encoded_phdr)
    assert r.encode_uhdr() == encoded_uhdr

    r.encrypt()

    assert r.payload == unhexlify(wrapped_key)
    assert hexlify(r.encode()) == hexlify(cbor2.dumps(expected))


@pytest.mark.parametrize("phdr, uhdr, d1, crv, d_hex",
                         [
                             ({CoseHeaderParam.ALG: CoseAlgorithm.ECDH_SS_HKDF_256},
                              {CoseHeaderParam.KID: "meriadoc.brandybuck@buckland.example".encode('utf-8')},
                              "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
                              SECP256R1,
                              'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf')

                         ])
def test_key_derivation_direct_recipient(phdr, uhdr, d1, crv, d_hex):
    d1 = hexlify(base64decode(d1))
    d1 = derive_private_key(int(d1, 16), crv(), openssl.backend)
    private_numbers = d1.private_numbers()

    assert hex(private_numbers.private_value) == hex(int(d_hex, 16))

    m = Enc0Message(payload=b'This is the content.')
    m.key = unhexlify('56074D506729CA40C4B4FE50C6439893')
    m.encrypt(alg=CoseAlgorithm.A128GCM, nonce=unhexlify(b'C9CF4DF2FE6C632BF7886413'))

    d2 = "02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3"
    d2 = derive_private_key(int(d2, 16), crv(), openssl.backend)

    shared_key = d2.exchange(ECDH(), d1.public_key())

    derived_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'', backend=openssl.backend)
    print(derived_key.derive(hexlify(shared_key)))


