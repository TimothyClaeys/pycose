import abc
from os import urandom

import cbor

from pycose import cosemessage
from pycose import crypto
from pycose.attributes import CoseAttrs


class EncCommon(cosemessage.CoseMessage, metaclass=abc.ABCMeta):
    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super(EncCommon, cls).from_cose_obj(cose_obj)
        try:
            msg.recipients = cose_obj.pop(0)
        except (IndexError, ValueError):
            msg.recipients = None
        return msg

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=None, key=None):
        super(EncCommon, self).__init__(p_header, u_header, payload)
        self._key = key

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, new_value):
        if isinstance(new_value, bytes):
            self._key = new_value
        else:
            raise ValueError("Key must be of type bytes")

    def decrypt(self, alg, nonce):
        self.payload = crypto.aead_encrypt(self.key, self._enc_structure, self.payload, alg, nonce)

    def encrypt(self, alg, nonce=urandom(12)):
        self.payload = crypto.aead_encrypt(self.key, self._enc_structure, self.payload, alg, nonce)

    def encode(self):
        raise NotImplementedError("Cannot instantiate abstract class EncCommon")

    @property
    def _enc_structure(self):
        enc_structure = list()
        enc_structure.append(self.context)

        if len(self.protected_header) == 0:
            enc_structure.append(bytes())
        else:
            enc_structure.append(self.encoded_protected_header)

        if self.external_aad is None:
            enc_structure.append(bytes())
        else:
            enc_structure.append(self.external_aad)

        aad = cbor.dumps(enc_structure)
        return aad
