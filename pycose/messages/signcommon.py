import abc
from typing import Type, TYPE_CHECKING

from pycose import headers
from pycose.keys.okp import OKPKey
from pycose.exceptions import CoseException
from pycose.keys.ec2 import EC2Key
from pycose.keys.rsa import RSAKey
from pycose.keys.keyops import VerifyOp, SignOp
from pycose.messages.cosemessage import CoseMessage

if TYPE_CHECKING:
    from pycose.keys.keyops import KEYOPS
    from pycose.algorithms import CoseAlg


class SignCommon(CoseMessage, metaclass=abc.ABCMeta):
    @property
    def signature(self):
        raise NotImplementedError

    @property
    def _sig_structure(self):
        raise NotImplementedError

    def _key_verification(self, alg: Type['CoseAlg'], ops: Type['KEYOPS']):

        if self.key is None:
            raise CoseException("Key cannot be None")

        if isinstance(self.key, EC2Key):
            self.key.verify(EC2Key, alg, [ops])
        elif isinstance(self.key, OKPKey):
            self.key.verify(OKPKey, alg, [ops])
        elif isinstance(self.key, RSAKey):
            self.key.verify(RSAKey, alg, [ops])
        else:
            raise CoseException('Wrong key type')

    def verify_signature(self, *args, **kwargs) -> bool:
        """
        Verifies the signature of a received COSE message.

        :returns: True for a valid signature or False for an invalid signature
        """
        alg = self.get_attr(headers.Algorithm)

        self._key_verification(alg, VerifyOp)

        return alg.verify(key=self.key, data=self._sig_structure, signature=self.signature)

    def compute_signature(self, *args, **kwargs) -> bytes:
        """
        Computes the signature over a COSE message.

        :returns: the signature
        """

        alg = self.get_attr(headers.Algorithm)

        self._key_verification(alg, SignOp)

        return alg.sign(key=self.key, data=self._sig_structure)
