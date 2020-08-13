import abc
from typing import Optional, Tuple

import cbor2

from pycose import cosemessage, crypto, CoseMessage
from pycose.algorithms import AlgorithmIDs
from pycose.cosebase import HeaderKeys
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
        super().__init__(phdr, uhdr, payload, external_aad, key)

        self.auth_tag = b''

    @property
    def key_bytes(self) -> bytes:
        if self.key is None:
            raise AttributeError('COSE_Key is not set')
        else:
            return self.key.key_bytes

    def verify_auth_tag(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None) -> bool:
        """ Verifies the authentication tag of a received message. """

        to_digest = self._mac_structure
        _alg, _key = self._get_crypt_params(alg, key)
        return crypto.verify_tag_wrapper(_key, self.auth_tag, to_digest, _alg)

    def compute_auth_tag(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None) -> bytes:
        """ Wrapper function to access the cryptographic primitives. """

        _alg, _key = self._get_crypt_params(alg, key)
        self.auth_tag = crypto.calc_tag_wrapper(_key, self._mac_structure, _alg)
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

    def _get_crypt_params(self,
                          alg: Optional[AlgorithmIDs],
                          key: Optional[SymmetricKey]) -> Tuple[AlgorithmIDs, bytes]:
        # if nothing is overridden by the function parameters, search in COSE headers
        _alg = alg if alg is not None else self.phdr.get(HeaderKeys.ALG)
        _alg = _alg if _alg is not None else self.uhdr.get(HeaderKeys.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        try:
            _key = key.key_bytes if key is not None else self.key_bytes
        except AttributeError:
            raise AttributeError("No key specified.")

        return _alg, _key
