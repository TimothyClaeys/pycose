"""
MACed Message with Recipients

COSE_Mac = [
      Headers,
      payload : bstr / nil,
      tag : bstr,
      recipients :[+COSE_recipient]
]
"""

import os
from typing import Optional, List, TYPE_CHECKING

from pycose import utils, headers
from pycose.exceptions import CoseException
from pycose.keys.keyops import MacCreateOp, MacVerifyOp
from pycose.keys.symmetric import SymmetricKey
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.messages import cosemessage, maccommon
from pycose.messages.recipient import CoseRecipient, DirectEncryption, DirectKeyAgreement, KeyWrap, \
    KeyAgreementWithKeyWrap

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK
    from pycose.messages.recipient import Recipient

CBOR = bytes


@cosemessage.CoseMessage.record_cbor_tag(97)
class MacMessage(maccommon.MacCommon):
    context = "MAC"
    cbor_tag = 97

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool) -> 'MacMessage':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.auth_tag = cose_obj.pop(0)

        try:
            msg.recipients = [CoseRecipient.create_recipient(r, allow_unknown_attributes, context='Mac_Recipient') for r
                              in cose_obj.pop(0)]
        except (IndexError, ValueError):
            msg.recipients = None

        return msg

    def __init__(self,
                 phdr: dict = None,
                 uhdr: dict = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 recipients: Optional[List[CoseRecipient]] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

        self._recipients = []
        self.recipients = recipients

    def encode(self, tag: bool = True, mac: bool = True, *args, **kwargs) -> CBOR:
        """ Encodes and protects the COSE_Mac message. """

        if mac:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.compute_tag()]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        if len(self.recipients):
            message.append([r.encode(target_alg=self.get_attr(headers.Algorithm)) for r in self.recipients])

        res = super(MacMessage, self).encode(message, tag)
        return res

    def verify_tag(self, recipient: 'Recipient', *args, **kwargs) -> bool:
        target_algorithm = self.get_attr(headers.Algorithm)

        # check if recipient exists
        if not CoseRecipient.has_recipient(recipient, self.recipients):
            raise CoseException(f"Cannot find recipient: {recipient}")

        CoseRecipient.verify_recipients(self.recipients)

        if isinstance(recipient, DirectEncryption):
            self.key = recipient.compute_cek(target_algorithm)

        elif isinstance(recipient, (DirectKeyAgreement, KeyWrap, KeyAgreementWithKeyWrap)):
            self.key = recipient.compute_cek(target_algorithm, MacVerifyOp)

        else:
            raise CoseException(f'Unsupported COSE recipient class: {type(recipient)}')

        return super(MacMessage, self).verify_tag()

    def compute_tag(self, *args, **kwargs) -> bytes:
        target_algorithm = self.get_attr(headers.Algorithm)

        r_types = CoseRecipient.verify_recipients(self.recipients)

        if DirectEncryption in r_types:
            self.key = self.recipients[0].compute_cek(target_algorithm)

        elif DirectKeyAgreement in r_types:
            self.key = self.recipients[0].compute_cek(target_algorithm, MacCreateOp)

        elif KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
            key_bytes = os.urandom(self.get_attr(headers.Algorithm).get_key_length())

            for r in self.recipients:
                if r.payload == b'':
                    r.payload = key_bytes
                else:
                    key_bytes = r.payload
                r.encrypt(target_algorithm)
            self.key = SymmetricKey(k=key_bytes, optional_params={KpAlg: target_algorithm, KpKeyOps: [MacCreateOp]})

        else:
            raise CoseException(f'Unsupported COSE recipient class: {r_types}')

        payload = super(MacMessage, self).compute_tag()

        return payload

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return \
            f'<COSE_Mac: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, ' \
            f'{utils.truncate(self.auth_tag)}, {self.recipients}]>'
