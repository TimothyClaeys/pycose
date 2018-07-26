# CDDL fragment MACed Message with Recipients
#
# COSE_Mac = [
#       Headers,
#       payload : bstr / nil,
#       tag : bstr,
#       recipients :[+COSE_recipient]
# ]
#


import binascii
from copy import deepcopy

import cbor

from pycose import cosemessage, maccommon
from pycose.attributes import CoseAttrs


@cosemessage.CoseMessage.record_cbor_tag(97)
class MacMessage(maccommon.MacCommon):
    context = "MAC"
    cbor_tag = 97

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=None, key=None, recipients=[]):
        super(MacMessage, self).__init__(
            deepcopy(p_header),
            deepcopy(u_header),
            payload,
            key
        )
        self._recipients = deepcopy(recipients)
        self._encoded_recipients = self._encode_recipients()

    @property
    def recipients(self):
        """Returns an array of recipients."""
        return self._recipients

    @recipients.setter
    def recipients(self, new_value):
        self._recipients.append(deepcopy(new_value))

    @property
    def encoded_recipients(self):
        return self._encode_recipients()

    def add_to_recipients(self, recpt_index, label, value, where):
        recipient = self._recipients[recpt_index]
        recipient.add_to_header(label, value, where)

    def find_in_recipients(self, label):
        raise NotImplementedError

    def encode(self):
        """Encodes the message into a CBOR array"""

        if len(binascii.hexlify(self.auth_tag)) not in [16, 32, 64, 96, 128]:
            raise ValueError("Tag has invalid size.")

        return cbor.dumps(cbor.Tag(self.cbor_tag, [self.encoded_protected_header, self.unprotected_header,
                                                   self.payload, self.auth_tag, self.encoded_recipients]))

    def _encode_recipients(self):
        recipient_list = []
        for rcpt in self._recipients:
            recipient_list.append([rcpt.encoded_protected_header, rcpt.unprotected_header, rcpt.ciphertext])
        return recipient_list
