import abc
from typing import Tuple, Optional

import cbor2

from pycose import cosemessage
from pycose import crypto
from pycose.attributes import CoseAlgorithm
from pycose.cosebase import HeaderKeys
from pycose.keys.symmetric import SymmetricKey


class EncCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """Getter for the context of the message."""
        raise NotImplementedError

    @property
    def key_bytes(self) -> bytes:
        if self.key is None:
            raise AttributeError('COSE_Key is not set')
        else:
            return self.key.key_bytes

    def decrypt(self,
                alg: Optional[CoseAlgorithm] = None,
                nonce: Optional[bytes] = None,
                key: Optional[SymmetricKey] = None) -> bytes:
        """ Decrypts the payload. """
        key, alg, nonce = self._get_crypt_params(alg, nonce, key)

        return crypto.aead_decrypt(key, self._enc_structure, self.payload, alg, nonce)

    def encrypt(self,
                alg: Optional[CoseAlgorithm] = None,
                nonce: Optional[bytes] = None,
                key: Optional[SymmetricKey] = None) -> bytes:
        """ Encrypts the payload. """
        key, alg, nonce = self._get_crypt_params(alg, nonce, key)

        return crypto.aead_encrypt(key, self._enc_structure, self.payload, alg, nonce)

    @property
    def _enc_structure(self) -> bytes:
        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad

    def _get_crypt_params(self,
                          alg: Optional[CoseAlgorithm],
                          nonce: Optional[bytes],
                          key: Optional[SymmetricKey]) -> Tuple[bytes, CoseAlgorithm, bytes]:
        try:
            _key = key.key_bytes if key is not None else self.key_bytes
        except AttributeError:
            raise AttributeError("No key specified.")

        # search in protected headers
        _alg = alg if alg is not None else self.phdr.get(HeaderKeys.ALG)
        _nonce = nonce if nonce is not None else self.phdr.get(HeaderKeys.IV)

        # search in unprotected headers
        _alg = _alg if _alg is not None else self.uhdr.get(HeaderKeys.ALG)
        _nonce = _nonce if _nonce is not None else self.uhdr.get(HeaderKeys.IV)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        if _nonce is None:
            raise AttributeError('No nonce specified.')

        return _key, _alg, _nonce
