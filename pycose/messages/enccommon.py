import abc
from typing import Optional, TYPE_CHECKING

import cbor2

from pycose import headers
from pycose.exceptions import CoseException
from pycose.keys.keyops import DecryptOp, EncryptOp
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.cosemessage import CoseMessage

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK


class EncCommon(CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """ Getter for the context of the message. """

        raise NotImplementedError()

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 *args,
                 **kwargs):
        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

    def decrypt(self, *args, **kwargs) -> bytes:
        """
        Decrypts the payload.

        :raises CoseException: When the key is not of type 'SymmetricKey'.
        :returns: plaintext as bytes
        """

        alg = self.get_attr(headers.Algorithm)
        nonce = self._get_nonce()

        if self.key is None:
            raise CoseException("Key cannot be None")

        self.key.verify(SymmetricKey, alg, [DecryptOp])

        return alg.decrypt(key=self.key, ciphertext=self.payload, external_aad=self._enc_structure, nonce=nonce)

    def encrypt(self, *args, **kwargs) -> bytes:
        """
        Encrypts the payload.

        :raises CoseException: When the key is not of type 'SymmetricKey'.
        :returns: ciphertext as bytes
        """

        # first check if key is set (since a part of the nonce can be stored in the key)
        if self.key is None:
            raise CoseException("Key cannot be None")

        alg = self.get_attr(headers.Algorithm)
        nonce = self._get_nonce()

        self.key.verify(SymmetricKey, alg, [EncryptOp])

        return alg.encrypt(key=self.key, data=self.payload, external_aad=self._enc_structure, nonce=nonce)

    @property
    def _enc_structure(self) -> bytes:
        """ Build the encryption context. """

        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad

    def _get_nonce(self):
        nonce = self.get_attr(headers.IV)

        if nonce is None and self.key.base_iv != b'':
            partial_iv = self.get_attr(headers.PartialIV)
            nonce = int.from_bytes(partial_iv, "big") ^ int.from_bytes(self.key.base_iv, "big")
            nonce = nonce.to_bytes((nonce.bit_length() + 7) // 8, byteorder="big")

        if nonce is None and self.key.base_iv == b'':
            raise CoseException('No IV found')

        return nonce
