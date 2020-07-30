import abc
from typing import Union

import cbor2

from pycose import cosemessage
from pycose import crypto
from pycose.attributes import CoseHeaderParam


class EncCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @classmethod
    def from_cose_obj(cls, cose_obj: list):
        msg = super().from_cose_obj(cose_obj)
        try:
            msg.recipients = cose_obj.pop(0)
        except (IndexError, ValueError):
            msg.recipients = None
        return msg

    def __init__(self, phdr: Union[dict, None], uhdr: Union[dict, None], payload: bytes, key: bytes):
        super().__init__(phdr, uhdr, payload)
        if isinstance(key, bytes):
            self._key = key
        else:
            raise ValueError('Key must be of type bytes')

    @property
    def key(self) -> bytes:
        return self._key

    @key.setter
    def key(self, new_value: bytes) -> None:
        if isinstance(new_value, bytes):
            self._key = new_value
        else:
            raise ValueError("Key must be of type bytes")

    def decrypt(self, alg: str, nonce: bytes) -> None:
        """ Decrypts the payload. """
        if self.key is None:
            raise AttributeError('No key specified')

        self.payload = crypto.aead_encrypt(self.key, self._enc_structure, self.payload, alg, nonce)

    def encrypt(self, alg: int = None, nonce: bytes = b'') -> None:
        """ Encrypts the payload. """
        if self.key is None:
            raise AttributeError('No key specified')

        # search in protected headers
        _alg = self.phdr.get(CoseHeaderParam.ALG) if alg is None else alg
        _nonce = self.phdr.get(CoseHeaderParam.IV) if nonce is b'' else nonce

        # search in unprotected headers
        _alg = self.uhdr.get(CoseHeaderParam.ALG) if _alg is None else _alg
        _nonce = self.uhdr.get(CoseHeaderParam.IV) if _nonce is None else _nonce

        if _alg is None:
            raise AttributeError('No algorithm specified')

        self.payload = crypto.aead_encrypt(self.key, self._enc_structure, self.payload, _alg, _nonce)

    def encode(self, tagged: bool = True):
        raise NotImplementedError("Cannot instantiate abstract class EncCommon")

    @property
    def _enc_structure(self) -> bytes:
        enc_structure = [self.context]

        if len(self.phdr) == 0:
            enc_structure.append(bytes())
        else:
            enc_structure.append(self.encode_phdr())

        if self.external_aad is None:
            enc_structure.append(bytes())
        else:
            enc_structure.append(self.external_aad)

        aad = cbor2.dumps(enc_structure)
        return aad

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError()
