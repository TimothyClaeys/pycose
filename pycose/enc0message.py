# CDDL fragment Encrypted Messages with Implicit Key
#
# COSE_Encrypt0 = [
#    Headers,
#    ciphertext: bstr / nil,
#]
#

import copy

import cbor

from pycose import cosemessage, enccommon
from pycose.attributes import CoseAttrs


@cosemessage.CoseMessage.record_cbor_tag(16)
class Enc0Message(enccommon.EncCommon):
    context = "Encrypt0"
    cbor_tag = 16

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=None, key=None):
        super(Enc0Message, self).__init__(
            p_header=copy.deepcopy(p_header),
            u_header=copy.deepcopy(u_header),
            payload=payload,
            key=key
        )
        self.is_encrypted = False

    def encode(self):
        return cbor.dumps(cbor.Tag(self.cbor_tag,
                            [self.encoded_protected_header, self.encoded_unprotected_header, self.payload]))

