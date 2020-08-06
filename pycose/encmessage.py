from typing import Union, List

import cbor2

from pycose import cosemessage, enccommon
from pycose.cosekey import SymmetricKey
from pycose.recipients import CoseRecipient


@cosemessage.CoseMessage.record_cbor_tag(96)
class EncMessage(enccommon.EncCommon):
    context = "Encrypt"
    cbor_tag = 96

    def __init__(self,
                 phdr: dict = None,
                 uhdr: dict = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: SymmetricKey = None,
                 recipients: List[Union[CoseRecipient]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super(EncMessage, self).__init__(phdr, uhdr, payload, external_aad, key)

        if recipients is None:
            self.recipients = []
        else:
            self.recipients = recipients

    def encode(self, tagged: bool = True) -> bytes:
        """ Encodes the message into a CBOR array """

        if tagged:
            res = cbor2.dumps(
                cbor2.CBORTag(self.cbor_tag, [self.encode_phdr(), self.encode_uhdr(), self.payload,
                                              [r.encode() for r in self.recipients]]))
        else:
            res = cbor2.dumps(
                [self.encode_phdr(), self.encode_uhdr(), self.payload, [r.encode() for r in self.recipients]])

        return res

    def __repr__(self) -> str:
        return f'<COSE_Encrypt:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t recipients={self.recipients}>'
