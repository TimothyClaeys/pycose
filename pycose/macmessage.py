"""
MACed Message with Recipients

COSE_Mac = [
      Headers,
      payload : bstr / nil,
      tag : bstr,
      recipients :[+COSE_recipient]
]
"""

from typing import Optional, List, Union, Tuple, Any

import cbor2

from pycose import cosemessage, maccommon
from pycose.algorithms import AlgorithmIDs
from pycose.keys.symmetric import SymmetricKey
from pycose.recipient import CoseRecipient, RcptParams


@cosemessage.CoseMessage.record_cbor_tag(97)
class MacMessage(maccommon.MacCommon):
    context = "MAC"
    cbor_tag = 97

    @classmethod
    def from_cose_obj(cls, cose_obj) -> 'MacMessage':
        msg = super().from_cose_obj(cose_obj)
        msg.auth_tag = cose_obj.pop(0)

        try:
            msg.recipients = [CoseRecipient.from_recipient_obj(r) for r in cose_obj.pop(0)]
        except (IndexError, ValueError):
            msg.recipients = None

        return msg

    def __init__(self,
                 phdr: dict = None,
                 uhdr: dict = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 recipients: Optional[List[CoseRecipient]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad)

        if recipients is None:
            self.recipients = []
        else:
            self.recipients = recipients

    def encode(self,
               key: SymmetricKey,
               alg: Optional[AlgorithmIDs] = None,
               mac_params: Optional[List[RcptParams]] = None,
               tagged: bool = True,
               mac: bool = True) -> bytes:
        """ Encodes and protects the COSE_Mac message. """

        # encode/encrypt the base fields
        if mac:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload, self.compute_tag(alg=alg, key=key)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if mac_params is None:
            mac_params = []

        if len(self.recipients) == len(mac_params):
            if len(mac_params) > 0:
                message.append(CoseRecipient.recursive_encode(self.recipients, mac_params))
        else:
            raise ValueError("List with cryptographic parameters should have the same length as the recipient list.")

        if tagged:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message))
        else:
            message = cbor2.dumps(message)

        return message

    def __repr__(self) -> str:
        return f'<COSE_Mac:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t auth_tag={self.auth_tag}\n' \
               f'\t recipients={self.recipients}>'
