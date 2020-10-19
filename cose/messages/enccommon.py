import abc
from typing import Optional

import cbor2

from cose.messages import cosemessage
from cose.attributes.algorithms import CoseAlgorithms
from cose.exceptions import CoseIllegalKeyType
from cose.keys.symmetric import SymmetricKey


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
        """
        Decrypts the payload.

        :param nonce: Nonce for decryption. Length tof the nonce depends on the AEAD. Nonce cannot be empty or None.
        :param key: A Symmetric COSE key object containing the symmetric key bytes and a optionally an AEAD algorithm.
        :param alg: If the 'alg' parameter is unset in the COSE key object, this parameter cannot be None.

        :raises ValueError: When the nonce is empty or None
        :raises CoseIllegalKeyType: When the key is not of type 'SymmetricKey'.

        :returns: plaintext as bytes
        """

        if nonce == b"" or nonce is None:
            raise ValueError(f"{nonce} is not a valid nonce value")

        if not isinstance(key, SymmetricKey):
            raise CoseIllegalKeyType("COSE key should be of type 'SymmetricKey', got {}".format(type(key)))

        return key.decrypt(ciphertext=self.payload, aad=self._enc_structure, nonce=nonce, alg=alg)

    def encrypt(self, nonce: bytes, key: SymmetricKey, alg: Optional[CoseAlgorithms] = None) -> bytes:
        """
        Encrypts the payload.

        :param nonce: Nonce for decryption. Length tof the nonce depends on the AEAD. Nonce cannot be empty or None.
        :param key: A Symmetric COSE key object containing the symmetric key bytes and a optionally an AEAD algorithm.
        :param alg: If the 'alg' parameter is unset in the COSE key object, this parameter cannot be None.

        :raises ValueError: When the nonce is empty or None
        :raises CoseIllegalKeyType: When the key is not of type 'SymmetricKey'.

        :returns: ciphertext as bytes
        """

        if nonce == b"" or nonce is None:
            raise ValueError(f"{nonce} is not a valid nonce value")

        if not isinstance(key, SymmetricKey):
            raise CoseIllegalKeyType("COSE key should be of type 'SymmetricKey', got {}".format(type(key)))

        return key.encrypt(plaintext=self.payload, aad=self._enc_structure, nonce=nonce, alg=alg)

    @property
    def _enc_structure(self) -> bytes:
        """ Build the encryption context. """

        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad
