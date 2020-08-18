from typing import Optional, Union

import cbor2

from pycose import cosemessage
from pycose.algorithms import AlgorithmIDs
from pycose.exceptions import CoseIllegalKeyType
from pycose.keys.cosekey import EllipticCurveTypes
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP


@cosemessage.CoseMessage.record_cbor_tag(18)
class Sign1Message(cosemessage.CoseMessage):
    context = "Signature1"
    cbor_tag = 18

    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super().from_cose_obj(cose_obj)
        msg.signature = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 private_key: Optional[Union[EC2, OKP]] = None,
                 public_key: Optional[Union[EC2, OKP]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad)

        self.signature = b''
        self.private_key = private_key
        self.public_key = public_key

    @property
    def private_key(self):
        return self._private_key

    @private_key.setter
    def private_key(self, new_key: Union[EC2, OKP]):
        if isinstance(new_key, EC2) or isinstance(new_key, OKP):
            self._private_key = new_key
        else:
            raise CoseIllegalKeyType(f"Expected type {type(EC2)} or type {type(OKP)}, instead got {type(new_key)}")

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, new_key: Union[EC2, OKP]):
        if isinstance(new_key, EC2) or isinstance(new_key, OKP):
            self._public_key = new_key
        else:
            raise CoseIllegalKeyType(f"Expected type {type(EC2)} or type {type(OKP)}, instead got {type(new_key)}")

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, new_signature):
        if type(new_signature) is not bytes:
            raise ValueError("signature must be of type 'bytes'")
        self._signature = new_signature

    @property
    def _sig_structure(self):
        """
        Create the sig_structure that needs to be signed
        :return: to_be_signed
        """
        sig_structure = [self.context]
        sig_structure = self._base_structure(sig_structure)

        sig_structure.append(self.payload)

        return cbor2.dumps(sig_structure)

    def verify_signature(self,
                         public_key: Optional[Union[EC2, OKP]],
                         alg: Optional[AlgorithmIDs] = None,
                         curve: Optional[EllipticCurveTypes] = None) -> bool:
        """
        Verifies the signature of a received message
        :return: True or raises an exception
        """
        if public_key is not None:
            self.public_key = public_key

        if self.public_key is None:
            raise ValueError("COSE Key cannot be None")

        return public_key.verify_signature(self._sig_structure, self.signature, alg)

    def compute_signature(self,
                          alg: Optional[AlgorithmIDs] = None,
                          key: Optional[Union[EC2, OKP]] = None):

        to_sign = self._sig_structure

        if key is not None:
            self.key = key

        if self.key is None:
            raise ValueError("COSE Key cannot be None")

        return self.key.compute_signature(to_sign, alg)

    def encode(self,
               tagged: bool = True,
               sign: bool = True,
               alg: Optional[AlgorithmIDs] = None,
               key: Optional[Union[EC2, OKP]] = None) -> bytes:
        """ Encodes the message into a CBOR array with or without a CBOR tag. """

        if sign:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload, self.compute_signature(alg, key)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if tagged:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message))
        else:
            res = cbor2.dumps(message)

        return res

    def __repr__(self):
        return f'<COSE_Sign1:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t signature={self.signature}>'
