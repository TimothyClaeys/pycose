"""
MACed Message with Recipients

COSE_Mac = [
      Headers,
      payload : bstr / nil,
      tag : bstr,
      recipients :[+COSE_recipient]
]
"""

from typing import Optional, List

import cbor2

from cose import CoseMessage
from cose.messages import cosemessage, maccommon
from cose.attributes.algorithms import CoseAlgorithms
from cose.keys.symmetric import SymmetricKey
from cose.messages.recipient import CoseRecipient, RcptParams


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
               alg: Optional[CoseAlgorithms] = None,
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
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._special_cbor_encoder)
        else:
            message = cbor2.dumps(message, default=self._special_cbor_encoder)

        return message

    def __repr__(self) -> str:
        return \
            f'<COSE_Mac0: [{self._phdr}, {self._uhdr}, {CoseMessage._truncate(self._payload)}, ' \
            f'{CoseMessage._truncate(self.auth_tag)}, {self.recipients}]>'
