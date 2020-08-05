import abc
from typing import Union, Tuple

import cbor2

from pycose import cosemessage
from pycose import crypto
from pycose.attributes import CoseHeaderParam
from pycose.cosekey import SymmetricKey


class EncCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @classmethod
    def from_cose_obj(cls, cose_obj: list):
        msg = super().from_cose_obj(cose_obj)
        try:
            msg.recipients = cose_obj.pop(0)
        except (IndexError, ValueError):
            msg.recipients = None
        return msg

    def __init__(self, phdr: Union[dict, None], uhdr: Union[dict, None], payload: bytes, key: SymmetricKey):
        super().__init__(phdr, uhdr, payload)
        self.key = key

    def decrypt(self, alg: str = None, nonce: bytes = None, key: bytes = None) -> None:
        """ Decrypts the payload. """

        key, alg, nonce = self._crypt_parameters(alg, nonce, key)

        self.payload = crypto.aead_encrypt(key, self._enc_structure, self.payload, alg, nonce)

    def encrypt(self, alg: int = None, nonce: bytes = None, key: bytes = None) -> None:
        """ Encrypts the payload. """

        key, alg, nonce = self._crypt_parameters(alg, nonce, key)

        self.payload = crypto.aead_encrypt(key, self._enc_structure, self.payload, alg, nonce)

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

    def _crypt_parameters(self, alg: int = None, nonce: bytes = None, key: bytes = None) -> Tuple[bytes, int, bytes]:
        if self.key is None and key is None:
            raise AttributeError('No key specified')
        elif self.key is not None:
            _key = self.key.keybytes
        else:
            _key = key

        # search in protected headers
        _alg = self.phdr.get(CoseHeaderParam.ALG) if alg is None else alg
        _nonce = self.phdr.get(CoseHeaderParam.IV) if nonce is None else nonce

        # search in unprotected headers
        _alg = self.uhdr.get(CoseHeaderParam.ALG) if _alg is None else _alg
        _nonce = self.uhdr.get(CoseHeaderParam.IV) if _nonce is None else _nonce

        if _alg is None:
            raise AttributeError('No algorithm specified')

        return _key, _alg, _nonce

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError()
