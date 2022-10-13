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
from pycose.keys.keyops import MacCreateOp
from pycose.messages import cosemessage, maccommon
from pycose.messages.recipient import CoseRecipient, DirectEncryption, DirectKeyAgreement, KeyWrap, \
    KeyAgreementWithKeyWrap

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK, SymmetricKey

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
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

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

    def compute_tag(self, *args, **kwargs) -> bytes:
        target_algorithm = self.get_attr(headers.Algorithm)

        r_types = CoseRecipient.verify_recipients(self.recipients)

        if DirectEncryption in r_types:
            # key should already be known
            payload = super(MacMessage, self).compute_tag()

        elif DirectKeyAgreement in r_types:
            self.key = self.recipients[0].compute_cek(target_algorithm, "encrypt")
            payload = super(MacMessage, self).compute_tag()

        elif KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
            key_bytes = os.urandom(self.get_attr(headers.Algorithm).get_key_length())

            for r in self.recipients:
                if r.payload == b'':
                    r.payload = key_bytes
                else:
                    key_bytes = r.payload
                r.encrypt(target_algorithm)
            self.key = SymmetricKey(k=key_bytes, alg=target_algorithm, key_ops=[MacCreateOp])
            payload = super(MacMessage, self).compute_tag()

        else:
            raise CoseException('Unsupported COSE recipient class')

        return payload

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return \
            f'<COSE_Mac: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, ' \
            f'{utils.truncate(self.auth_tag)}, {self.recipients}]>'
