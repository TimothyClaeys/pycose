import copy

import cbor

from pycose import crypto, cosemessage, signcommon
from pycose.attributes import CoseAttrs


@cosemessage.CoseMessage.record_cbor_tag(18)
class Sign1Message(signcommon.SignCommon):
    context = "Signature1"
    cbor_tag = 18

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=b'', signature=b'', key=b''):
        super(Sign1Message, self).__init__(
            copy.deepcopy(p_header),
            copy.deepcopy(u_header),
            payload)
        self._key = key
        self._signature = signature

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, new_value):
        self._key = new_value

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, new_value):
        self._signature = new_value

    @property
    def _sig_structure(self):
        """
        create the sig_structure that needs to be signed
        :return: to_be_signed
        """
        sig_structure = list()
        sig_structure.append(self.context)

        # add empty_or_serialized_map
        if len(self.protected_header) == 0:
            sig_structure.append(bytes())
        else:
            sig_structure.append(self.encoded_protected_header)

        if self.external_aad is None:
            sig_structure.append(bytes())
        else:
            sig_structure.append(self.external_aad)

        if self.payload is None:
            raise ValueError("Payload cannot be empty for tag computation")

        if isinstance(self.payload, str):
            sig_structure.append(bytes(self.payload, 'utf-8'))
        elif isinstance(self.payload, bytes):
            sig_structure.append(self.payload)

        to_be_signed = cbor.dumps(sig_structure)
        return to_be_signed

    def verify_signature(self, alg, curve='P-256', signer=None):
        """
        Verifies the authentication tag of a received message
        :return: True or raises an exception
        """
        to_sign = self._sig_structure
        return crypto.ec_verify_wrapper(self.key, to_sign, self.signature, alg, curve)

    def encode(self):
        """
        Encodes the message into a CBOR array with the appropriate cbor tag attached
        :return: COSE message
        """
        return cbor.dumps(
            cbor.Tag(self.cbor_tag, [self.encoded_protected_header, self.unprotected_header, self.payload, self.signature]))
