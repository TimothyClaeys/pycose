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


@cosemessage.CoseMessage.record_cbor_tag(17)
class Mac0Message(maccommon.MacCommon):
    context = "MAC0"
    cbor_tag = 17

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=None, key=None):
        super(Mac0Message, self).__init__(
            copy.deepcopy(p_header),
            copy.deepcopy(u_header),
            payload
        )
        self._key = key

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, new_value):
        if isinstance(new_value, bytes):
            self._key = new_value
        else:
            raise ValueError("Key must be of type bytes")

    def encode(self):
        """
        Encodes the message into a CBOR array
        :return: COSE message
        """
        if len(binascii.hexlify(self.auth_tag)) in [16, 32, 64, 96, 128]:
            return cbor.dumps(cbor.Tag(self.cbor_tag,
                                       [self.encoded_protected_header, self.unprotected_header, self.payload,
                                        self.auth_tag]))
        else:
            raise ValueError("Tag has invalid size")
