# CDDL fragment MACed Messages with Implicit Key
#
# COSE_Mac = [
#       Headers,
#       payload : bstr / nil,
#       tag : bstr
# ]
#

import binascii
import copy

import cbor

from pycose import cosemessage, maccommon
from pycose.attributes import CoseAttrs
from pycose.exceptions import *


@cosemessage.CoseMessage.record_cbor_tag(17)
class Mac0Message(maccommon.MacCommon):
    context = "MAC0"
    cbor_tag = 17

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=None, key=None):
        super(Mac0Message, self).__init__(
            p_header=copy.deepcopy(p_header),
            u_header=copy.deepcopy(u_header),
            payload=payload,
            key=key
        )

    def __repr__(self):
        repr = cbor.loads(cbor.dumps(cbor.Tag(self.cbor_tag,
                                              [self.encoded_protected_header, self.encoded_unprotected_header,
                                               self.payload, self.auth_tag])))
        t = repr.tag
        v = [binascii.hexlify(element) if isinstance(element, bytes) else element for element in repr.value]

        return str((t, v))

    def encode(self):
        """Encodes the message into a CBOR array with the correct CBOR tag."""

        if len(binascii.hexlify(self.auth_tag)) not in [16, 32, 64, 96, 128]:
            raise CoseInvalidTag("The length of the COSE auth tag must be in [16, 32, 64, 96, 128]")

        return cbor.dumps(cbor.Tag(self.cbor_tag,
                                   [self.encoded_protected_header, self.encoded_unprotected_header, self.payload,
                                    self.auth_tag]))
