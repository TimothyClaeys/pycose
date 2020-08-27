from typing import Optional, Union

import cbor2

from pycose import cosemessage, signcommon
from pycose.algorithms import AlgorithmIDs
from pycose.keys.cosekey import EllipticCurveType
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP


@cosemessage.CoseMessage.record_cbor_tag(18)
class Sign1Message(cosemessage.CoseMessage, signcommon.SignCommon):
    context = "Signature1"
    cbor_tag = 18

    @classmethod
    def from_cose_obj(cls, cose_obj) -> 'Sign1Message':
        msg = super().from_cose_obj(cose_obj)
        msg.signature = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b''):

        super().__init__(phdr, uhdr, payload, external_aad)
        self.signature = b''

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, value):
        if not isinstance(value, bytes):
            TypeError("Signature must be of type 'bytes'")

        self._signature = value

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

    def encode(self,
               private_key: Union[EC2, OKP],
               alg: Optional[AlgorithmIDs] = None,
               curve: Optional[EllipticCurveType] = None,
               tagged: bool = True,
               sign: bool = True) -> bytes:
        """ Encodes the message into a CBOR array with or without a CBOR tag. """

        if sign:
            message = [self.encode_phdr(),
                       self.encode_uhdr(),
                       self.payload,
                       self.compute_signature(alg=alg, private_key=private_key, curve=curve)]
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
