# CDDL fragment MACed Message with Recipients
#
# COSE_Sign = [
#    Headers,
#    payload: bstr / nil,
#    signatures: [+ COSE_Signature]
# ]
#


import copy

import cbor

from pycose import cosemessage, crypto, signcommon
from pycose.attributes import CoseAttrs


@cosemessage.CoseMessage.record_cbor_tag(98)
class SignMessage(signcommon.SignCommon):
    context = "Signature"
    cbor_tag = 98

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=b'', signers=CoseAttrs(), key=b''):
        super(SignMessage, self).__init__(
            copy.deepcopy(p_header),
            copy.deepcopy(u_header),
            payload)
        self._key = key
        self._signers = self.__convert_to_coseattrs(copy.deepcopy(signers))

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, new_value):
        self._key = new_value

    @property
    def signers(self):
        correct_sig_format = []
        sig_struct = copy.deepcopy(self._signers)
        for key in sig_struct:
            correct_sig_format.append(copy.deepcopy(sig_struct[key]))

        for sig in correct_sig_format:
            # encode protected attributes 'comme il faut'
            if not sig[0]:
                sig[0] = bytes()
            else:
                sig[0] = cbor.dumps(sig[0])

        return correct_sig_format

    @signers.setter
    def signers(self, new_value):
        new_value = copy.deepcopy(new_value)
        if new_value is not None and len(new_value) != 0:
            self._signers = CoseAttrs()
            key = 1
            for sig in new_value:
                self._signers[key] = sig
                key += 1

            # cbor decode the byte string protected header, so that we can do lookups

            for sig in self._signers:
                if len(self._signers[sig][0]) != 0:
                    protected_signature = CoseAttrs()
                    new_value = cbor.loads(self._signers[sig][0])
                    for key, value in new_value.items():
                        protected_signature[key] = value

                    self._signers[sig][0] = copy.deepcopy(protected_signature)
                else:
                    self._signers[sig][0] = CoseAttrs()

            for sig in self._signers:
                if len(self._signers[sig][1]) != 0:
                    unprotected_signature = CoseAttrs()
                    for key, value in self._signers[sig][1].items():
                        unprotected_signature[key] = value

                    self._signers[sig][1] = copy.deepcopy(unprotected_signature)
                else:
                    self._signers[sig][1] = CoseAttrs()
        else:
            self._signers = CoseAttrs()

    @property
    def _sig_structure(self):
        """
        create the sig_structure that needs to be signed
        :return: to_be_signed
        """
        sig_structure = list()
        sig_structure.append(self.context)

        # add empty_or_serialized_map
        if len(self.encoded_protected_header) == 0:
            sig_structure.append(bytes())
        else:
            sig_structure.append(self.encoded_protected_header)

        # add empty_or_serialized_map
        for signature in self.signers:
            if len(signature[0]) == 0:
                sig_structure.append(bytes())
            else:
                sig_structure.append(signature[0])

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
        return crypto.ec_verify_wrapper(self.key, to_sign, self._signers[signer][2], alg, curve)

    def encode(self):
        """
        Encodes the message into a CBOR array
        :return: COSE message
        """
        return cbor.dumps(cbor.Tag(
            self.cbor_tag, [self.encoded_protected_header, self.unprotected_header, self.payload, self.signers]))

    # ------- Everything above is shared with sign1message ------- #

    def add_to_signers(self, signer, label, value, where):
        if signer in self._signers:
            if where == "PROTECTED":
                self._signers[signer][0][label] = value

            if where == "UNPROTECTED":
                self._signers[signer][1][label] = value

        else:
            # make new recipient
            signature = [CoseAttrs(), CoseAttrs(), b'']
            # add the attribute
            if where == "PROTECTED":
                signature[0][label] = value

            if where == "UNPROTECTED":
                signature[1][label] = value

            self._signers[signer] = signature

    def add_signature_to_signers(self, signer, signature):
        if signer in self._signers:
            self._signers[signer][2] = signature
        else:
            # make new container
            container = [CoseAttrs(), CoseAttrs(), b'']
            # add the attribute
            container[2] = signature
            self._signers[signer] = container

    def find_in_signers(self, label):
        found = None
        for sig in self._signers:
            if label in self._signers[sig][0]:
                found = self._signers[sig][0][label]

            if label in self._signers[sig][1]:
                found = self._signers[sig][1][label]

        return found
