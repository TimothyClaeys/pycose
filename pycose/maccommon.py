import abc

import cbor

from pycose import cosemessage, crypto
from pycose.attributes import CoseAttrs


class MacCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super(MacCommon, cls).from_cose_obj(cose_obj)
        msg.auth_tag = cose_obj.pop(0)
        try:
            msg.recipients = cose_obj.pop(0)
        except (IndexError, ValueError):
            msg.recipients = None
        return msg

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=None, key=None):
        super(MacCommon, self).__init__(p_header, u_header, payload)
        self._auth_tag = None
        self._key = key

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, new_value):
        if isinstance(new_value, bytes):
            self._key = new_value
        else:
            raise ValueError("Key must be of type bytes.")

    @property
    def auth_tag(self):
        return self._auth_tag

    @auth_tag.setter
    def auth_tag(self, new_value):
        if not isinstance(new_value, bytes):
            raise TypeError("Auth tag must be of type bytes")
        else:
            self._auth_tag = new_value

    def verify_auth_tag(self, alg):
        """Verifies the authentication tag of a received message."""
        to_digest = self._mac_structure
        return crypto.verify_tag_wrapper(self.key, self.auth_tag, to_digest, alg)

    def compute_auth_tag(self, alg):
        """Wrapper function to access the cryptographic primitives."""
        to_digest = self._mac_structure
        self.auth_tag = crypto.calc_tag_wrapper(self.key, to_digest, alg)

    @abc.abstractmethod
    def encode(self):
        raise NotImplementedError("Cannot instantiate abstract class MacCommon")

    @property
    def _mac_structure(self):
        """Create the mac_structure that needs to be MAC'ed."""
        mac_structure = list()
        mac_structure.append(self.context)

        # add empty_or_serialized_map
        if len(self.protected_header) == 0:
            mac_structure.append(bytes())
        else:
            mac_structure.append(self.encoded_protected_header)

        if self.external_aad is None:
            mac_structure.append(bytes())
        else:
            mac_structure.append(self.external_aad)

        if self.payload is None:
            raise ValueError("Payload cannot be empty for tag computation")

        if isinstance(self.payload, str):
            mac_structure.append(bytes(self.payload, 'utf-8'))
        elif isinstance(self.payload, bytes):
            mac_structure.append(self.payload)

        to_be_maced = cbor.dumps(mac_structure)
        return to_be_maced
