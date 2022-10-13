import os
from typing import List, Optional, TYPE_CHECKING

from pycose import utils, headers
from pycose.exceptions import CoseException
from pycose.keys.keyops import EncryptOp
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.keys.symmetric import SymmetricKey
from pycose.messages import enccommon, cosemessage
from pycose.messages.recipient import DirectEncryption, DirectKeyAgreement, KeyWrap, KeyAgreementWithKeyWrap, \
    CoseRecipient

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK
    from pycose.messages.recipient import Recipient

CBOR = bytes


@cosemessage.CoseMessage.record_cbor_tag(96)
class EncMessage(enccommon.EncCommon):
    context = "Encrypt"
    cbor_tag = 96

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool) -> 'EncMessage':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)

        try:
            msg.recipients = [CoseRecipient.create_recipient(r, allow_unknown_attributes, context='Enc_Recipient') for r
                              in cose_obj.pop(0)]
        except (IndexError, ValueError):
            msg.recipients = []
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 recipients: Optional[List['Recipient']] = None,
                 *args,
                 **kwargs):
        """
        Create a COSE_Encrypt message.

        :param phdr: Protected header.
        :param uhdr: Unprotected header.
        :param payload: The payload of the COSE_Encrypt message.
        :param external_aad: External additional data (is authenticated by not included in the final message)
        :param recipients: An optional list of :class:`~pycose.messages.recipient.CoseRecipient` objects.
        """

        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

        self._recipients = []
        self.recipients = recipients

    def encode(self, tag: bool = True, encrypt: bool = True, *args, **kwargs) -> CBOR:
        """ Encodes and protects the COSE_Encrypt message """

        # encode/wrap_cek the base fields
        if encrypt:
            message = [self.phdr_encoded, self.uhdr_encoded, self.encrypt()]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        if len(self.recipients):
            message.append([r.encode(target_alg=self.get_attr(headers.Algorithm)) for r in self.recipients])

        res = super(EncMessage, self).encode(message, tag)
        return res

    def encrypt(self, *args, **kwargs) -> bytes:
        target_algorithm = self.get_attr(headers.Algorithm)

        r_types = CoseRecipient.verify_recipients(self.recipients)

        if DirectEncryption in r_types:
            # key should already be known
            payload = super(EncMessage, self).encrypt()

        elif DirectKeyAgreement in r_types:
            self.key = self.recipients[0].compute_cek(target_algorithm, "encrypt")
            payload = super(EncMessage, self).encrypt()

        elif KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
            key_bytes = os.urandom(self.get_attr(headers.Algorithm).get_key_length())
            for r in self.recipients:
                if r.payload == b'':
                    r.payload = key_bytes
                else:
                    key_bytes = r.payload
                r.encrypt(target_algorithm)
            self.key = SymmetricKey(k=key_bytes, optional_params={KpAlg: target_algorithm, KpKeyOps: [EncryptOp]})
            payload = super(EncMessage, self).encrypt()

        else:
            raise CoseException('Unsupported COSE recipient class')

        return payload

    def decrypt(self, recipient: 'Recipient', *args, **kwargs) -> bytes:
        target_algorithm = self.get_attr(headers.Algorithm)

        # check if recipient exists
        if not CoseRecipient.has_recipient(recipient, self.recipients):
            raise CoseException(f"Cannot find recipient: {recipient}")

        r_types = CoseRecipient.verify_recipients(self.recipients)

        if DirectEncryption in r_types:
            # key should already be known
            payload = super(EncMessage, self).decrypt()

        elif DirectKeyAgreement in r_types or KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
            self.key = recipient.compute_cek(target_algorithm, "decrypt")
            payload = super(EncMessage, self).decrypt()
        else:
            raise CoseException('Unsupported COSE recipient class')

        return payload

    @property
    def recipients(self) -> List['Recipient']:
        return self._recipients

    @recipients.setter
    def recipients(self, recipients: List['Recipient']) -> None:

        if recipients is None:
            self._recipients = []
        else:
            for r in recipients:
                if not issubclass(type(r), CoseRecipient):
                    raise TypeError(f"Recipient must be a subclass of {CoseRecipient}")
                self._recipients.append(r)

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()
        rcpts = str(self.recipients)

        return f'<COSE_Encrypt: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, {rcpts}]>'
