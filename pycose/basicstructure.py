from typing import Dict, Union

import cbor2
import abc

from pycose.attributes import CoseHeaderParam as Hp, CoseAlgorithm as Alg


class BasicCoseStructure(metaclass=abc.ABCMeta):
    """ Basic COSE information buckets. """

    def __init__(self, phdr: dict = None, uhdr: dict = None, payload: bytes = b''):
        self._phdr = {} if phdr is None else phdr.copy()
        self._uhdr = {} if uhdr is None else uhdr.copy()

        self._payload = payload  # can be plaintext or ciphertext

    @property
    def phdr(self) -> dict:
        return self._phdr

    @phdr.setter
    def phdr(self, new_phdr: dict) -> None:
        self._phdr = new_phdr.copy()

    @property
    def uhdr(self) -> dict:
        return self._uhdr

    @uhdr.setter
    def uhdr(self, new_uhdr: dict) -> None:
        self._uhdr = new_uhdr.copy()

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, new_payload: bytes) -> None:
        self._payload = new_payload  # can be plaintext or ciphertext

    def phdr_update(self, phdr_params: dict) -> None:
        self._phdr.update(phdr_params)

    def uhdr_update(self, uhdr_params: dict) -> None:
        self._uhdr.update(uhdr_params)

    def encode_phdr(self) -> bytes:
        """ Encode the protected header. """
        if len(self._phdr):
            return cbor2.dumps(self._phdr)
        else:
            return b''

    def encode_uhdr(self) -> dict:
        """ Encode the unprotected header. """
        return self._uhdr

    @classmethod
    def parse_cose_hdr(cls, hdr: Dict[int, Union[int, bytes]]) -> Dict[Union[Hp, bytes], Union[Alg, bytes]]:
        return {(Hp(k) if Hp.has_value(k) else k): (Alg(v) if Hp.has_value(k) and Hp(k) == Hp.ALG else v)
                for k, v in hdr.items()}

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError("Cannot instantiate abstract class BasicCoseStructure")
