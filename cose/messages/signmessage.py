# CDDL fragment MACed Message with Recipients
#
# COSE_Sign = [
#    Headers,
#    payload: bstr / nil,
#    signatures: [+ COSE_Signature]
# ]
#
from typing import Optional, List

import cbor2

from cose import CoseMessage
from cose.messages import cosemessage
from cose.messages.signer import CoseSignature, SignerParams


@cosemessage.CoseMessage.record_cbor_tag(98)
class SignMessage(cosemessage.CoseMessage):
    cbor_tag = 98

    @classmethod
    def from_cose_obj(cls, cose_obj) -> 'SignMessage':
        """ Parses COSE_Sign messages. """

        msg: 'SignMessage' = super().from_cose_obj(cose_obj)

        for r in cose_obj.pop(0):
            msg.append_signer(CoseSignature.from_signature_obj(r))

        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 signers: Optional[List[CoseSignature]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, payload)

        if signers is None:
            self._signers = list()
        else:
            self._signers = signers

    @property
    def signers(self):
        return self._signers

    def encode(self, sign_params: Optional[List[SignerParams]] = None, tagged: bool = True) -> bytes:
        """ Encodes and protects the COSE_Sign message."""

        signers = []
        message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if sign_params is None:
            sign_params = []

        if len(sign_params) == len(self.signers):
            for signer, p in zip(self.signers, sign_params):
                signers.append(signer.encode(p))
        else:
            raise ValueError("List with cryptographic parameters should have the same length as the recipient list.")

        message.append(signers)

        if tagged:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._special_cbor_encoder)
        else:
            message = cbor2.dumps(message, default=self._special_cbor_encoder)

        return message

    def append_signer(self, signer: CoseSignature) -> None:
        """ Appends a new signer (COSE_Signature) to the COSE_Sign message. """

        if not isinstance(signer, CoseSignature):
            raise TypeError(f"Signer must be of type {CoseSignature}")

        signer._parent_msg = self
        self._signers.append(signer)

    def __repr__(self) -> str:
        return f'<COSE_Sign: [{self._phdr}, {self._uhdr}, {CoseMessage._truncate(self._payload)}, {self._signers}]>'
