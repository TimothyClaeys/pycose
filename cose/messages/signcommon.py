import abc
from typing import Optional, Union, TYPE_CHECKING

from cose import cosebase
from cose.exceptions import CoseIllegalKeyType
from cose.keys.ec2 import EC2
from cose.keys.okp import OKP

if TYPE_CHECKING:
    from cose.attributes.algorithms import CoseAlgorithms, CoseEllipticCurves


class SignCommon(cosebase.CoseBase, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """Getter for the context of the message."""
        raise NotImplementedError

    def __init__(self, phdr: Optional[dict] = None, uhdr: Optional[dict] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr)

    @property
    def signature(self):
        raise NotImplementedError

    @property
    def _sig_structure(self):
        raise NotImplementedError

    def verify_signature(self,
                         public_key: Union[EC2, OKP],
                         alg: Optional['CoseAlgorithms'] = None,
                         curve: Optional['CoseEllipticCurves'] = None) -> bool:
        """
        Verifies the signature of a received COSE message.

        :param public_key: A COSE key of type EC2 or OKP
        :param alg: An optional CoseAlgorithm
        :param curve: An optional CoseEllipticCurve
        :raises CoseIllegalKeyType: When the key type is not of EC2 or OKP
        :raises CoseIllegalAlgorithm: When the algorithm configuration is invalid
        :returns: True for a valid signature or False for an invalid signature
        """
        if not isinstance(public_key, EC2) and not isinstance(public_key, OKP):
            raise CoseIllegalKeyType("COSE key should be of type 'EC2' or 'OKP', got {}".format(type(public_key)))

        return public_key.verify(self._sig_structure, self.signature, alg, curve)

    def compute_signature(self,
                          private_key: Union[EC2, OKP] = None,
                          alg: Optional['CoseAlgorithms'] = None,
                          curve: Optional['CoseEllipticCurves'] = None) -> bytes:
        """
        Computes the signature over a COSE message.

        :param private_key: A COSE key of type EC2 or OKP
        :param alg: An optional CoseAlgorithm
        :param curve: An optional CoseEllipticCurve
        :raises CoseIllegalKeyType: When the key type is not of EC2 or OKP
        :raises CoseIllegalAlgorithm: When the algorithm configuration is invalid
        :returns: True or False
        """

        if not isinstance(private_key, EC2) and not isinstance(private_key, OKP):
            raise CoseIllegalKeyType("COSE key should be of type 'EC2' or 'OKP', got {}".format(type(private_key)))

        return private_key.sign(self._sig_structure, alg, curve)
