# CDDL fragment MACed Messages with Implicit Key
#
# COSE_Mac = [
#       Headers,
#       payload : bstr / nil,
#       tag : bstr
# ]
#

import binascii

import cbor

import cosemessage
import maccommon


@cosemessage.CoseMessage.record_cbor_tag(17)
class Mac0Message(maccommon.MacCommon):
    context = "MAC0"
    cbor_tag = 17

    def __init__(self, protected_header=None, unprotected_header=None, payload=None, key=None):
        """
        :param protected_header: dictionary containing the protected header attributes, will be encoded as serialized
        map or empty byte string
        :param unprotected_header: dictionary containing the protected header attributes, encoded as cbor map
        :param payload: byte string
        :param key: MAC0 key is implicitly known in the MAC0 structure
        """
        super(Mac0Message, self).__init__(protected_header, unprotected_header, payload)
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
            return cbor.dumps(cbor.Tag(self.cbor_tag,[self.protected_header, self.unprotected_header, self.payload, self.auth_tag]))
        else:
            raise ValueError("Tag has invalid size")
