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
                 nonce: Optional[bytes] = b""):

        super().__init__(phdr, uhdr, payload, external_aad)

        self.key = key
        self.nonce = nonce

    @property
    def key(self) -> Optional[SymmetricKey]:
        return self._key

    @key.setter
    def key(self, new_key: Optional[SymmetricKey]):
        if new_key is not None and isinstance(new_key, SymmetricKey):
            self._key = new_key
        elif new_key is None:
            self._key = new_key
        else:
            raise CoseIllegalKeyType(f"Expected type {type(SymmetricKey)}, instead got {type(new_key)}")

    @property
    def nonce(self) -> bytes:
        return self._nonce

    @nonce.setter
    def nonce(self, new_nonce: bytes):
        if new_nonce is not None and isinstance(new_nonce, bytes):
            self._nonce = new_nonce
        elif new_nonce is None:
            self._nonce = new_nonce
        else:
            raise CoseIllegalKeyType(f"Expected type {bytes}, instead got {type(new_nonce)}")

    def decrypt(self,
                nonce: bytes = b'',
                key: Optional[SymmetricKey] = None,
                alg: Optional[AlgorithmIDs] = None) -> bytes:
        """ Decrypts the payload. """

        if nonce != b"":
            self.nonce = nonce

        if self.nonce == b"":
            raise ValueError("Nonce for encryption/decryption cannot be empty")

        if key is not None:
            self.key = key

        if self.key is None:
            raise ValueError("COSE Key cannot be None")

        return self.key.decrypt(self.payload, self._enc_structure, self.nonce, alg)

    def encrypt(self,
                nonce: bytes = b"",
                key: Optional[SymmetricKey] = None,
                alg: Optional[AlgorithmIDs] = None) -> bytes:
        """ Encrypts the payload. The provided arguments overwrite the default ones. """

        return self.key.encrypt(self.payload, self._enc_structure, self.nonce, alg)

    @property
    def _enc_structure(self) -> bytes:
        """ Build the encryption context. """

        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad
