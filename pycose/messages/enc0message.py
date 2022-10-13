"""
COSE_Encrypt0: Encrypted Messages with Implicit Key

COSE_Encrypt0 = [
   Headers,
   ciphertext: bstr / nil,
]
"""

from typing import Optional, TYPE_CHECKING

from pycose import utils
from pycose.messages import enccommon, cosemessage

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK

CBOR = bytes


@cosemessage.CoseMessage.record_cbor_tag(16)
class Enc0Message(enccommon.EncCommon):
    context = "Encrypt0"
    cbor_tag = 16

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool) -> 'Enc0Message':
        return super().from_cose_obj(cose_obj, allow_unknown_attributes)

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 *args,
                 **kwargs):

        """
        Create a COSE_encrypt0 message.

        :param phdr: Protected header bucket.
        :param uhdr: Unprotected header bucket.
        :param payload: The payload (will be encrypted and authenticated).
        :param external_aad: External data (is authenticated but not transported in the message).
        :param key: The Symmetric COSE key for encryption/decryption of the message

        :returns: Returns a COSE Encrypt0 message object.
        """

        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

    def encode(self, tag: bool = True, encrypt: bool = True, *args, **kwargs) -> CBOR:
        """
        Encode and protect the COSE_Encrypt0 message.

        :param tag: Boolean value which indicates if the COSE message will have a CBOR tag.
        :param encrypt: Boolean which activates or deactivates the payload protection.

        :return: Returns a CBOR-encoded COSE Encrypt0 message.
        """

        if encrypt:
            message = [self.phdr_encoded, self.uhdr_encoded, self.encrypt()]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        res = super(Enc0Message, self).encode(message, tag)
        return res

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Encrypt0: [{phdr}, {uhdr}, {utils.truncate(self._payload)}]>'
