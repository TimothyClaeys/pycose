import abc
from typing import Optional, TYPE_CHECKING

import cbor2

from pycose import headers
from pycose.exceptions import CoseException
from pycose.keys.keyops import MacVerifyOp, MacCreateOp
from pycose.keys.symmetric import SymmetricKey
from pycose.messages import cosemessage

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK


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
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

        self.auth_tag = b''

    def verify_tag(self, *args, **kwargs) -> bool:
        """ Verifies the authentication tag of a received message. """

        alg = self.get_attr(headers.Algorithm)

        if self.key is None:
            raise CoseException("Key cannot be None")

        self.key.verify(SymmetricKey, alg, [MacVerifyOp])

        return alg.verify_tag(key=self.key, tag=self.auth_tag, data=self._mac_structure)

    def compute_tag(self, *args, **kwargs) -> bytes:
        """ Computes the authentication tag of a COSE_Mac or COSE_Mac0 message. """

        alg = self.get_attr(headers.Algorithm)

        if self.key is None:
            raise CoseException("Key cannot be None")

        self.key.verify(SymmetricKey, alg, [MacCreateOp])

        self.auth_tag = alg.compute_tag(key=self.key, data=self._mac_structure)
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
