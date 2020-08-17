import abc
from typing import Optional

import cbor2

from pycose import cosemessage
from pycose.algorithms import AlgorithmIDs
from pycose.exceptions import CoseIllegalKeyType
from pycose.keys.symmetric import SymmetricKey


class EncCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """ Getter for the context of the message. """

        raise NotImplementedError

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional[SymmetricKey] = None,
                 nonce: bytes = b''):

        super().__init__(phdr, uhdr, payload, external_aad)

        self.key = key
        self.nonce = nonce

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, new_key):
        if isinstance(new_key, SymmetricKey):
            self._key = new_key
        else:
            raise CoseIllegalKeyType(f"Expected type {type(SymmetricKey)}, instead got {type(new_key)}")

    def decrypt(self,
                nonce: Optional[bytes] = None,
                key: Optional[SymmetricKey] = None,
                alg: Optional[AlgorithmIDs] = None) -> bytes:
        """ Decrypts the payload. """

        if key is not None:
            self.key = key

        if self.key is None:
            raise ValueError("COSE Key cannot be None")

        if nonce is not None:
            self.nonce = nonce

        if self.nonce is None:
            raise ValueError("Nonce for encryption/decryption cannot be empty")

        return self.key.decrypt(self.payload, self._enc_structure, nonce, alg)

    def encrypt(self,
                nonce: Optional[bytes] = None,
                key: Optional[SymmetricKey] = None,
                alg: Optional[AlgorithmIDs] = None) -> bytes:
        """ Encrypts the payload. """

        if key is not None:
            self.key = key

        if self.key is None:
            raise ValueError("COSE Key cannot be None")

        if nonce is not None:
            self.nonce = nonce

        if self.nonce is None:
            raise ValueError("Nonce for encryption/decryption cannot be empty")

        return self.key.encrypt(self.payload, self._enc_structure, nonce, alg)

    @property
    def _enc_structure(self) -> bytes:
        """ Build the encryption context. """

        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad

