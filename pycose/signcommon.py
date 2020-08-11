import abc
from typing import Optional, Union, Tuple

from pycose import cosemessage, crypto
from pycose.attributes import CoseAlgorithm, CoseHeaderParam
from pycose.cosekey import EC2, OKP


class SignCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):

    @property
    @abc.abstractmethod
    def _sig_structure(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def signature(self):
        raise NotImplementedError

    @signature.setter
    @abc.abstractmethod
    def signature(self, new_signature):
        raise NotImplementedError

    def verify_signature(self, alg: Optional[CoseAlgorithm] = None, key: Optional[Union[EC2, OKP]] = None) -> bool:
        """
        Verifies the signature of a received message
        :return: True or raises an exception
        """
        _alg, _key = self._get_crypt_params(alg, key)

        return crypto.ec_verify_wrapper(_key, self._sig_structure, self.signature, _alg)

    def compute_signature(self,
                          alg: Optional[CoseAlgorithm] = None,
                          key: Optional[Union[EC2, OKP]] = None):

        to_sign = self._sig_structure

        _alg, _key = self._get_crypt_params(alg, key)
        return crypto.ec_sign_wrapper(_key, to_sign, _alg)

    def _get_crypt_params(self,
                          alg: Optional[CoseAlgorithm],
                          key: Optional[Union[EC2, OKP]]) -> Tuple[CoseAlgorithm, Union[EC2, OKP]]:

        # if nothing is overridden by the function parameters, search in COSE headers
        _alg = alg if alg is not None else self.phdr.get(CoseHeaderParam.ALG)
        _alg = _alg if _alg is not None else self.uhdr.get(CoseHeaderParam.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        try:
            _key = key if key is not None else self.key
        except AttributeError:
            raise AttributeError("No key specified.")

        return _alg, _key
