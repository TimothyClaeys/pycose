# CDDL fragment Encrypted Messages with Implicit Key
#
# COSE_Encrypt0 = [
#    Headers,
#    ciphertext: bstr / nil,
# ]
#

import cbor2

from pycose import cosemessage, enccommon
from pycose.cosekey import SymmetricKey


@cosemessage.CoseMessage.record_cbor_tag(16)
class Enc0Message(enccommon.EncCommon):
    context = "Encrypt0"
    cbor_tag = 16

    def __init__(self,
                 phdr: dict = None,
                 uhdr: dict = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: SymmetricKey = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super(Enc0Message, self).__init__(phdr, uhdr, payload, external_aad, key)

    def encode(self, tagged: bool = True) -> bytes:
        if tagged:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, [self.encode_phdr(), self.encode_uhdr(), self.encrypt()]))
        else:
            res = cbor2.dumps([self.encode_phdr(), self.encode_uhdr(), self.encrypt()])

        return res

    def __repr__(self):
        return f'<COSE_Encrypt0:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}>'
