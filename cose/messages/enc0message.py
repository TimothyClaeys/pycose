"""
COSE_Encrypt0: Encrypted Messages with Implicit Key

COSE_Encrypt0 = [
   Headers,
   ciphertext: bstr / nil,
]
"""

from typing import Optional

import cbor2

from cose import CoseMessage
from cose.messages import enccommon, cosemessage
from cose.attributes.algorithms import CoseAlgorithms
from cose.keys.symmetric import SymmetricKey


@cosemessage.CoseMessage.record_cbor_tag(16)
class Enc0Message(enccommon.EncCommon):
    context = "Encrypt0"
    cbor_tag = 16

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> 'Enc0Message':
        return super().from_cose_obj(cose_obj)

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b''):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad)

    def encode(self,
               nonce: bytes,
               key: SymmetricKey,
               alg: Optional[CoseAlgorithms] = None,
               tagged: bool = True,
               encrypt: bool = True) -> bytes:
        """ Encode and protect the COSE_Encrypt0 message. """

        if encrypt:
            message = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(nonce=nonce, alg=alg, key=key)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if tagged:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._special_cbor_encoder)
        else:
            res = cbor2.dumps(message, default=self._special_cbor_encoder)

        return res

    def __repr__(self) -> str:
        return f'<COSE_Encrypt0: [{self._phdr}, {self._uhdr}, {CoseMessage._truncate(self._payload)}]>'
