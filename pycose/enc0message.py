"""
COSE_Encrypt0: Encrypted Messages with Implicit Key

COSE_Encrypt0 = [
   Headers,
   ciphertext: bstr / nil,
]
"""

from typing import Optional

import cbor2

from pycose import cosemessage, enccommon
from pycose.cosekey import SymmetricKey


@cosemessage.CoseMessage.record_cbor_tag(16)
class Enc0Message(enccommon.EncCommon):
    context = "Encrypt0"
    cbor_tag = 16

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional[SymmetricKey] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key)

    def encode(self,
               tagged: bool = True,
               encrypt: bool = True,
               alg: Optional[int] = None,
               nonce: Optional[bytes] = None,
               key: Optional[SymmetricKey] = None) -> bytes:

        if encrypt:
            message = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(alg, nonce, key)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if tagged:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message))
        else:
            res = cbor2.dumps(message)

        return res

    def __repr__(self):
        return f'<COSE_Encrypt0:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}>'
