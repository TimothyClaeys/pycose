from copy import deepcopy

from pycose.attributes import CoseAttrs
from pycose.basicstructure import BasicCoseStructure


class CoseRecipient(BasicCoseStructure):
    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), ciphertext=b'', rcpt_key=None):
        super(CoseRecipient, self).__init__(
            deepcopy(p_header),
            deepcopy(u_header),
        )
        self._ciphertext = ciphertext
        self._rcpt_key = rcpt_key

    @property
    def ciphertext(self):
        return self._ciphertext

    @property
    def rcpt_key(self):
        return self._rcpt_key

    @rcpt_key.setter
    def rcpt_key(self, key):
        self._rcpt_key = key
