import abc
from typing import Optional, Union

from pycose import cosemessage
from pycose.algorithms import AlgorithmIDs
from pycose.exceptions import CoseIllegalKeyType, CoseInvalidAlgorithm, CoseIllegalCurve
from pycose.keys.cosekey import EllipticCurveTypes
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP


class SignCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """Getter for the context of the message."""
        raise NotImplementedError

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b''):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad)

        self.signature = b''

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, new_signature):
        if type(new_signature) is not bytes:
            raise ValueError("signature must be of type 'bytes'")
        self._signature = new_signature

    @property
    def _sig_structure(self):
        raise NotImplementedError

    def verify_signature(self,
                         public_key: Union[EC2, OKP],
                         alg: Optional[AlgorithmIDs] = None,
                         curve: Optional[EllipticCurveTypes] = None) -> bool:
        """
        Verifies the signature of a received message
        :return: True or raises an exception
        """
        self._sanitize_args(public_key, alg, curve)

        return public_key.verify(self._sig_structure, self.signature, alg, curve)

    def compute_signature(self,
                          private_key: Union[EC2, OKP] = None,
                          alg: Optional[AlgorithmIDs] = None,
                          curve: Optional[EllipticCurveTypes] = None) -> bytes:
        """
        Computes the signature of a COSE message
        :return: True or raises an exception
        """

        self._sanitize_args(private_key, alg, curve)

        return private_key.sign(self._sig_structure, alg)

    @classmethod
    def _sanitize_args(cls,
                       key: Union[EC2, OKP],
                       alg: Optional[AlgorithmIDs] = None,
                       curve: Optional[EllipticCurveTypes] = None) -> None:
        """ Sanitize parameters for encryption/decryption algorithms. """

        if key is None:
            raise CoseIllegalKeyType("COSE Key cannot be None")

        if key.alg is None and alg is None:
            raise CoseInvalidAlgorithm("COSE algorithm cannot be None")

        if key.crv is None and curve is None:
            raise CoseIllegalCurve("Ellipic curve cannot be None")
