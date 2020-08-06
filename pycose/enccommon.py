import abc
from typing import Tuple

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

    def __init__(self, phdr: dict, uhdr: dict, payload: bytes, external_data: bytes = b'', key: SymmetricKey = None):
        super().__init__(phdr, uhdr, payload, external_data, key)

    @property
    def key_bytes(self) -> bytes:
        if self.key is None:
            raise AttributeError('COSE_Key is not set')
        else:
            return self.key.key_bytes

    def decrypt(self, alg: int = None, nonce: bytes = None, key: bytes = None) -> None:
        """ Decrypts the payload. """

        key, alg, nonce = self._get_crypt_parameters(alg, nonce, key)

        self.payload = crypto.aead_encrypt(key, self._enc_structure, self.payload, alg, nonce)

    def encrypt(self, alg: int = None, nonce: bytes = None, key: bytes = None) -> None:
        """ Encrypts the payload. """

        key, alg, nonce = self._get_crypt_parameters(alg, nonce, key)

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

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError()

    def _get_crypt_parameters(self, alg: int, nonce: bytes, key: bytes) -> Tuple[bytes, int, bytes]:

        _key = key if key is not None else self.key_bytes

        # search in protected headers
        _alg = alg if alg is not None else self.phdr.get(CoseHeaderParam.ALG)
        _nonce = nonce if nonce is not None else self.phdr.get(CoseHeaderParam.IV)

        # search in unprotected headers
        _alg = _alg if _alg is not None else self.uhdr.get(CoseHeaderParam.ALG)
        _nonce = _nonce if _nonce is not None else self.uhdr.get(CoseHeaderParam.IV)

        if _alg is None:
            raise AttributeError('No algorithm specified')

        return _key, _alg, _nonce
