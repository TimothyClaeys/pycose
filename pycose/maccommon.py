import abc
from typing import List, Optional, Tuple

import cbor2

from pycose import cosemessage, crypto
from pycose.attributes import CoseAlgorithm, CoseHeaderParam
from pycose.cosekey import SymmetricKey
from pycose.recipient import CoseRecipient


class MacCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super().from_cose_obj(cose_obj)
        msg.auth_tag = cose_obj.pop(0)

        try:
            msg.recipients = [CoseRecipient.from_recipient_obj(r) for r in cose_obj.pop(0)]
        except (IndexError, ValueError):
            msg.recipients = None
        return msg

    def __init__(self,
                 phdr: dict = None,
                 uhdr: dict = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: SymmetricKey = None,
                 recipients: Optional[List[CoseRecipient]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key)

        self.auth_tag = b''

        if recipients is None:
            self.recipients = []
        else:
            self.recipients = recipients

    @property
    def key_bytes(self) -> bytes:
        if self.key is None:
            raise AttributeError('COSE_Key is not set')
        else:
            return self.key.key_bytes

    def verify_auth_tag(self, alg: Optional[CoseAlgorithm] = None, key: Optional[SymmetricKey] = None):
        """ Verifies the authentication tag of a received message. """

        to_digest = self._mac_structure
        _alg, _key = self._get_crypt_params(alg, key)
        return crypto.verify_tag_wrapper(_key, self.auth_tag, to_digest, _alg)

    def compute_auth_tag(self, alg: Optional[CoseAlgorithm] = None, key: Optional[SymmetricKey] = None):
        """ Wrapper function to access the cryptographic primitives. """

        _alg, _key = self._get_crypt_params(alg, key)
        return crypto.calc_tag_wrapper(_key, self._mac_structure, _alg)

    @abc.abstractmethod
    def encode(self, tagged: bool = True):
        raise NotImplementedError("Cannot instantiate abstract class MacCommon")

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
                          alg: Optional[CoseAlgorithm],
                          key: Optional[SymmetricKey]) -> Tuple[CoseAlgorithm, bytes]:
        # if nothing is overridden by the function parameters, search in COSE headers
        _alg = alg if alg is not None else self.phdr.get(CoseHeaderParam.ALG)
        _alg = _alg if _alg is not None else self.uhdr.get(CoseHeaderParam.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        try:
            _key = key.key_bytes if key is not None else self.key_bytes
        except AttributeError:
            raise AttributeError("No key specified.")

        return _alg, _key
