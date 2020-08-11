from typing import Union, List, Optional, Tuple, Any

import cbor2

from pycose import cosemessage, enccommon
from pycose.attributes import CoseAlgorithm
from pycose.cosekey import SymmetricKey
from pycose.recipient import CoseRecipient


@cosemessage.CoseMessage.record_cbor_tag(96)
class EncMessage(enccommon.EncCommon):
    context = "Encrypt"
    cbor_tag = 96

    @classmethod
    def from_cose_obj(cls, cose_obj: list):
        msg = super().from_cose_obj(cose_obj)

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
                 key: SymmetricKey = None,
                 recipients: Optional[List[CoseRecipient]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key)

        if recipients is None:
            self.recipients = []
        else:
            self.recipients = recipients

    def encode(self,
               tagged: bool = True,
               encrypt: bool = True,
               alg: Optional[CoseAlgorithm] = None,
               nonce: Optional[bytes] = None,
               key: Optional[SymmetricKey] = None,
               crypto_params:
               Tuple[Tuple[bool, Union[CoseAlgorithm, None], Union[SymmetricKey, None], Union[Tuple[Any], None]]] = None
               ) -> bytes:
        """ Encodes the message as a CBOR array """

        # encode/encrypt the base fields
        if encrypt:
            message = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(alg, nonce, key)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if len(self.recipients) > 0:
            message.append(CoseRecipient.recusive_encode(self.recipients, crypto_params))

        if tagged:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message))
        else:
            message = cbor2.dumps(message)

        return message

    def __repr__(self) -> str:
        return f'<COSE_Encrypt:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t recipients={self.recipients}>'
