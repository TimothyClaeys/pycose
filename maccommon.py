import abc

import cbor

import cosemessage
import crypto


class MacCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super(MacCommon, cls).from_cose_obj(cose_obj)
        msg.auth_tag = cose_obj.pop(0)
        try:
            msg.recipients = cose_obj.pop(0)
        except IndexError:
            msg.recipients = None
        return msg

    def __init__(self, protected_header=None, unprotected_header=None, payload=None, auth_tag=None):
        super(MacCommon, self).__init__(protected_header, unprotected_header, payload)
        self._auth_tag = auth_tag

    @property
    @abc.abstractmethod
    def key(self):
        NotImplementedError("Cannot not instantiate abstract class MacCommon")

    @key.setter
    @abc.abstractmethod
    def key(self, new_value):
        NotImplementedError("Cannot not instantiate abstract class MacCommon")

    @property
    def _mac_structure(self):
        """
        create the mac_structure that needs to be MAC'ed
        :return: to_be_maced
        """
        mac_structure = list()
        mac_structure.append(self.context)

        # add empty_or_serialized_map
        if len(self.protected_header) == 0:
            mac_structure.append(bytes())
        else:
            mac_structure.append(self.protected_header)

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

    @property
    def auth_tag(self):
        return self._auth_tag

    @auth_tag.setter
    def auth_tag(self, new_value):
        self._auth_tag = new_value

    def verify_auth_tag(self, alg):
        """
        Verifies the authentication tag of a received message
        :return: True or raises an exception
        """
        to_digest = self._mac_structure
        return crypto.hmac_verify_wrapper(self.key, self.auth_tag, to_digest, alg)

    def compute_auth_tag(self, alg):
        """
        pass key, byte-string-to-mac and algorithm found in the header buckets to the hmac wrapper
        :return: tag
        """
        to_digest = self._mac_structure
        self.auth_tag = crypto.hmac_wrapper(self.key, to_digest, alg)
