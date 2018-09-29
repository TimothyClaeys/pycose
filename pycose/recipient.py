from copy import deepcopy

from pycose.attributes import CoseAttrs
from pycose.basicstructure import BasicCoseStructure
from pycose.enccommon import EncCommon
from pycose.maccommon import MacCommon


class CoseRecipient(BasicCoseStructure):
    def __init__(self, alg, nonce, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=b'', rcpt_key=None):
        super(CoseRecipient, self).__init__()
        self.alg = alg
        self.nonce = nonce


class CoseMacRecipient(CoseRecipient, MacCommon):
    def __init__(self, alg, nonce, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=b'', rcpt_key=None):
        super(CoseMacRecipient, self).__init__(
            alg,
            nonce,
            deepcopy(p_header),
            deepcopy(u_header),
            payload,
            rcpt_key,
        )


class CoseEncRecipient(CoseRecipient, EncCommon):
    def __init__(self, alg, nonce, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=b'', rcpt_key=None):
        super(CoseEncRecipient, self).__init__(
            alg,
            nonce,
            deepcopy(p_header),
            deepcopy(u_header),
            payload,
            rcpt_key
        )

