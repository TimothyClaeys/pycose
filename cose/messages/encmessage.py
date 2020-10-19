from typing import List, Optional

import cbor2

from cose import CoseMessage
from cose.messages import enccommon, cosemessage
from cose.attributes.algorithms import CoseAlgorithms
from cose.keys.symmetric import SymmetricKey
from cose.messages.recipient import CoseRecipient, RcptParams


@cosemessage.CoseMessage.record_cbor_tag(96)
class EncMessage(enccommon.EncCommon):
    context = "Encrypt"
    cbor_tag = 96

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> 'EncMessage':
        msg = super().from_cose_obj(cose_obj)

        try:
            msg.recipients = [CoseRecipient.from_recipient_obj(r) for r in cose_obj.pop(0)]
        except (IndexError, ValueError):
            msg.recipients = []
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 recipients: Optional[List[CoseRecipient]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad)

        if recipients is None:
            self.recipients = list()
        else:
            self.recipients = recipients

    def encode(self,
               nonce: bytes,
               key: SymmetricKey,
               alg: Optional[CoseAlgorithms] = None,
               enc_params: Optional[List[RcptParams]] = None,
               tagged: bool = True,
               encrypt: bool = True) -> bytes:
        """ Encodes and protects the COSE_Encrypt message """

        # encode/encrypt the base fields
        if encrypt:
            message = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(nonce=nonce, key=key, alg=alg)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if enc_params is None:
            enc_params = []

        if len(self.recipients) == len(enc_params):
            if len(enc_params) > 0:
                message.append(CoseRecipient.recursive_encode(self.recipients, enc_params))
        else:
            raise ValueError("List with cryptographic parameters should have the same length as the recipient list.")

        if tagged:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._special_cbor_encoder)
        else:
            message = cbor2.dumps(message, default=self._special_cbor_encoder)

        return message

    def __repr__(self) -> str:
        return \
            f'<COSE_Encrypt: [{self._phdr}, {self._uhdr}, {CoseMessage._truncate(self._payload)}, {self.recipients}]>'
