import abc
from typing import Optional

import cbor2

from cose.messages import cosemessage
from cose.attributes.algorithms import CoseAlgorithms
from cose.exceptions import CoseIllegalKeyType
from cose.keys.symmetric import SymmetricKey


class MacCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """Getter for the context of the message."""
        raise NotImplementedError

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b''):
        super().__init__(phdr, uhdr, payload, external_aad)

        self.auth_tag = b''

    def verify_tag(self, key: SymmetricKey, alg: Optional[CoseAlgorithms] = None) -> bool:
        """ Verifies the authentication tag of a received message. """

        if not isinstance(key, SymmetricKey):
            raise CoseIllegalKeyType("COSE key should be of type 'SymmetricKey', got {}".format(type(key)))

        return key.verify_tag(self.auth_tag, self._mac_structure, alg)

    def compute_tag(self, key: SymmetricKey, alg: Optional[CoseAlgorithms] = None) -> bytes:
        """ Computes the authentication tag of a COSE_Mac or COSE_Mac0 message. """

        if not isinstance(key, SymmetricKey):
            raise CoseIllegalKeyType("COSE key should be of type 'SymmetricKey', got {}".format(type(key)))

        self.auth_tag = key.compute_tag(self._mac_structure, alg)
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
