# CDDL fragment MACed Messages with Implicit Key
#
# COSE_Mac = [
#       Headers,
#       payload : bstr / nil,
#       tag : bstr
# ]
#

from typing import Optional

import cbor2

from pycose import cosemessage, maccommon
from pycose.algorithms import AlgorithmIDs
from pycose.keys.symmetric import SymmetricKey


@cosemessage.CoseMessage.record_cbor_tag(17)
class Mac0Message(maccommon.MacCommon):
    context = "MAC0"
    cbor_tag = 17

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> 'Mac0Message':
        msg = super().from_cose_obj(cose_obj)
        msg.auth_tag = cose_obj.pop(0)

        return msg

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
               key: SymmetricKey,
               alg: Optional[AlgorithmIDs] = None,
               tagged: bool = True,
               mac: bool = True) -> bytes:
        """ Encode and protect the COSE_Mac0 message. """

        if mac:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload, self.compute_tag(alg=alg, key=key)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if tagged:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message))
        else:
            res = cbor2.dumps(message)

        return res

    def __repr__(self) -> str:
        return f'<COSE_Mac0:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t tag={self.auth_tag}>'
