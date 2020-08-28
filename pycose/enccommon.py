import abc
from typing import Optional

import cbor2

from pycose import cosemessage
from pycose.algorithms import CoseAlgorithms
from pycose.exceptions import CoseIllegalKeyType, CoseInvalidAlgorithm
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
                 external_aad: bytes = b''):

        super().__init__(phdr, uhdr, payload, external_aad)

    def decrypt(self, nonce: bytes, key: SymmetricKey, alg: Optional[CoseAlgorithms] = None) -> bytes:
        """ Decrypts the payload. """

        self._sanitize_args(nonce=nonce, key=key, alg=alg)

        return key.decrypt(ciphertext=self.payload, aad=self._enc_structure, nonce=nonce, alg=alg)

    def encrypt(self, nonce: bytes, key: SymmetricKey, alg: Optional[CoseAlgorithms] = None) -> bytes:
        """ Encrypts the payload. The provided arguments overwrite the default ones. """

        self._sanitize_args(nonce=nonce, key=key, alg=alg)

        return key.encrypt(plaintext=self.payload, aad=self._enc_structure, nonce=nonce, alg=alg)

    @property
    def _enc_structure(self) -> bytes:
        """ Build the encryption context. """

        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad

    @classmethod
    def _sanitize_args(cls, nonce: bytes, key: SymmetricKey, alg: Optional[CoseAlgorithms] = None) -> None:
        """ Sanitize parameters for encryption/decryption algorithms. """

        if nonce == b"" or nonce is None:
            raise ValueError(f"{nonce} is not a valid nonce value")

        if key is None:
            raise CoseIllegalKeyType("COSE Key cannot be None")

        if key.alg is None and alg is None:
            raise CoseInvalidAlgorithm("COSE algorithm cannot be None")
