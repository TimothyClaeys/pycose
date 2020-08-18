import abc
from typing import Optional, Tuple

import cbor2

from pycose import cosemessage, CoseMessage
from pycose.algorithms import AlgorithmIDs
from pycose.cosebase import HeaderKeys
from pycose.exceptions import CoseIllegalKeyType
from pycose.keys.symmetric import SymmetricKey


class MacCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """Getter for the context of the message."""
        raise NotImplementedError

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> CoseMessage:
        msg = super().from_cose_obj(cose_obj)
        msg.auth_tag = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional[SymmetricKey] = None):
        super().__init__(phdr, uhdr, payload, external_aad)

        self.key = key
        self.auth_tag = b''

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, new_key):
        if isinstance(new_key, SymmetricKey):
            self._key = new_key
        else:
            raise CoseIllegalKeyType(f"Expected type {type(SymmetricKey)}, instead got {type(new_key)}")

    def verify_tag(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None) -> bool:
        """ Verifies the authentication tag of a received message. """

        to_digest = self._mac_structure

        if key is not None:
            self.key = key

        if self.key is None:
            raise ValueError("COSE Key cannot be None")

        return self.key.verify_tag(self.auth_tag, to_digest, alg)

    def compute_tag(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None) -> bytes:
        """ Wrapper function to access the cryptographic primitives. """

        if key is not None:
            self.key = key

        if self.key is None:
            raise ValueError("COSE Key cannot be None")

        self.auth_tag = self.key.compute_tag(self._mac_structure, alg)
        return self.auth_tag

    @property
    def _mac_structure(self) -> bytes:
        """ Create the mac_structure that needs to be MAC'ed. """

        # add empty_or_serialized_map
        mac_structure = [self.context]
        mac_structure = self._base_structure(mac_structure)

        if self.payload is None:
            raise ValueError("Payload cannot be empty for tag computation")

        mac_structure.append(self.payload)
        return cbor2.dumps(mac_structure)

