from itertools import zip_longest
from typing import Union, List, Tuple

import cbor2

from pycose import cosemessage, enccommon
from pycose.recipients import CoseRecipient


@cosemessage.CoseMessage.record_cbor_tag(96)
class EncMessage(enccommon.EncCommon):
    context = "Encrypt"
    cbor_tag = 96

    def __init__(self,
                 phdr: dict = None,
                 uhdr: dict = None,
                 payload: bytes = b'',
                 key: bytes = b'',
                 recipients: List[Union[CoseRecipient]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super(EncMessage, self).__init__(phdr, uhdr, payload, key)

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

    def encrypt(self, alg: int = None, nonce: bytes = b'', rcpt_algs: List[Tuple[int, bytes]] = None) -> None:
        """ Encrypts the COSE_Encrypt message. """
        super(EncMessage, self).encrypt(alg, nonce)

        if rcpt_algs is None:
            rcpt_algs = []

        for r, a in zip_longest(self.recipients, rcpt_algs):
            r.encrypt(*a)

    def __repr__(self) -> str:
        return f'<COSE_Encrypt:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t recipients={self.recipients}>'
