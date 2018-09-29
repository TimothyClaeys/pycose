import binascii
from copy import deepcopy

import cbor

from pycose import cosemessage, enccommon
from pycose.attributes import CoseAttrs
from pycose.recipient import CoseRecipient


@cosemessage.CoseMessage.record_cbor_tag(97)
class EncMessage(enccommon.EncCommon):
    context = "ENC"
    cbor_tag = 96

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=None, key=None, recipients=[]):
        super(EncMessage, self).__init__(
            deepcopy(p_header),
            deepcopy(u_header),
            payload,
            key
        )

        for rcpt in recipients:
            if not isinstance(rcpt, CoseRecipient):
                raise ValueError()
        self._recipients = deepcopy(recipients)

        self._encoded_recipients = self.__encode_recipients()

    @property
    def recipients(self):
        """Returns an array of recipients."""
        return self._recipients

    @recipients.setter
    def recipients(self, new_value):
        for rcpt in new_value:
            if not isinstance(rcpt, CoseRecipient):
                raise ValueError()
        self._recipients = deepcopy(new_value)

    @property
    def encoded_recipients(self):
        return self.__encode_recipients()

    def change_recipient(self, recpt_index, label, value, where):
        recipient = self._recipients[recpt_index]
        recipient.add_to_header(label, value, where)

    def add_to_recpients(self, rcpt):
        if not isinstance(rcpt, CoseRecipient):
            raise ValueError()
        else:
            self._recipients.append(rcpt)

    def find_in_recipients(self, label):
        raise NotImplementedError

    def encode(self):
        """Encodes the message into a CBOR array"""

        if len(binascii.hexlify(self.auth_tag)) not in [16, 32, 64, 96, 128]:
            raise ValueError("Tag has invalid size.")

        return cbor.dumps(cbor.Tag(self.cbor_tag, [self.encoded_protected_header, self.unprotected_header,
                                                   self.payload, self.encoded_recipients]))

    def __encode_recipients(self):
        recipient_list = []
        for rcpt in self._recipients:
            rcpt.encrypt(rcpt.alg)
            recipient_list.append([rcpt.encoded_protected_header, rcpt.encoded_unprotected_header, rcpt.payload])
        return recipient_list
