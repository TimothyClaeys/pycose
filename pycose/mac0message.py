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
from pycose.cosekey import SymmetricKey


@cosemessage.CoseMessage.record_cbor_tag(17)
class Mac0Message(maccommon.MacCommon):
    context = "MAC0"
    cbor_tag = 17

    def __init__(self,
                 phdr: dict = None,
                 uhdr: dict = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: SymmetricKey = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key)

    def encode(self,
               tagged: bool = True,
               mac: bool = True,
               alg: Optional[int] = None,
               key: Optional[SymmetricKey] = None) -> bytes:
        """ Encodes the message into a CBOR array with or without a CBOR tag. """

        if mac:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload, self.compute_auth_tag(alg, key)]
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
               f'\t payload={self._payload}\n' \
               f'\t tag={self.auth_tag}>'
