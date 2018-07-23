import abc

from pycose import cosemessage, crypto


class SignCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super(SignCommon, cls).from_cose_obj(cose_obj)

        msg.signers = cose_obj.pop(0)
        return msg

    @property
    @abc.abstractmethod
    def key(self):
        NotImplementedError("Cannot not instantiate abstract class CoseMessage")

    @key.setter
    @abc.abstractmethod
    def key(self, new_value):
        NotImplementedError("Cannot not instantiate abstract class MacCommon")

    @property
    @abc.abstractmethod
    def _sig_structure(self):
        raise NotImplementedError("Cannot instantiate abstract SignCommon class")

    @abc.abstractmethod
    def verify_signature(self, alg, curve='P-256', signer=None):
        raise NotImplementedError("Cannot instantiate abstract SignCommon class")

    def compute_signature(self, alg='ES256', curve='P-256'):
        """
        pass key, byte-string-to-mac and algorithm found in the header buckets to the hmac wrapper
        :return: tag
        """

        to_sign = self._sig_structure
        return crypto.ec_sign_wrapper(self.key, to_sign, alg, curve)
