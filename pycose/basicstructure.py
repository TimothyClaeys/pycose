import abc
from typing import Dict, Union, Any, Optional

import cbor2

from pycose.attributes import CoseHeaderParam as Hp, CoseAlgorithm as Alg
from pycose.cosekey import CoseKey


class BasicCoseStructure(metaclass=abc.ABCMeta):
    """ Basic COSE information buckets. """

    def __init__(self, phdr: Optional[dict] = None, uhdr: Optional[dict] = None, payload: bytes = b''):
        if phdr is None:
            phdr = {}

        if uhdr is None:
            uhdr = {}

        if type(phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")

        if type(uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")

        self._phdr = phdr.copy()
        self._uhdr = uhdr.copy()

        # can be plaintext or ciphertext
        if type(payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = payload

    @property
    def phdr(self) -> dict:
        return self._phdr

    @phdr.setter
    def phdr(self, new_phdr: dict) -> None:
        if type(new_phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr = new_phdr.copy()

    @property
    def uhdr(self) -> dict:
        return self._uhdr

    @uhdr.setter
    def uhdr(self, new_uhdr: dict) -> None:
        if type(new_uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr = new_uhdr.copy()

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, new_payload: bytes) -> None:
        if type(new_payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = new_payload  # can be plaintext or ciphertext

    def phdr_update(self, phdr_params: dict) -> None:
        if type(phdr_params) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr.update(phdr_params)

    def uhdr_update(self, uhdr_params: dict) -> None:
        if type(uhdr_params) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
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
    def parse_cose_hdr(cls, hdr: Dict[Union[Hp, bytes], Any]) -> Dict[Union[Hp, bytes], Any]:
        return {(Hp(k) if Hp.has_value(k) else k): cls._parse_hdr_value(k, v) for k, v in hdr.items()}

    @classmethod
    def _parse_hdr_value(cls, key: Union[Hp, bytes], value: Union[Hp, bytes, dict]) -> Any:
        if not Hp.has_value(key):
            return value

        if key == Hp.ALG:
            return Alg(value)
        elif key == Hp.EPHEMERAL_KEY:
            return CoseKey.decode(value)
        else:
            return value

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError()
