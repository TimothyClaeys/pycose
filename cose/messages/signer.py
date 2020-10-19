from typing import Optional, Union, TYPE_CHECKING

import cbor2
from dataclasses import dataclass

from cose import CoseMessage
from cose.messages import signcommon
from cose.keys.ec import EC2
from cose.keys.okp import OKP

if TYPE_CHECKING:
    from cose.attributes.algorithms import CoseAlgorithms, CoseEllipticCurves


@dataclass
class SignerParams:
    private_key: Union[EC2, OKP]
    alg: Optional['CoseAlgorithms'] = None
    curve: Optional['CoseEllipticCurves'] = None
    sign: bool = True


class CoseSignature(signcommon.SignCommon):
    context = "Signature"

    @classmethod
    def from_signature_obj(cls, cose_signature_obj: list) -> 'CoseSignature':
        """ Parses COSE_Signature objects. """

        msg: 'CoseSignature' = super().from_cose_obj(cose_signature_obj)
        msg.signature = cose_signature_obj.pop()

        return msg

    def __init__(self, phdr: Optional[dict], uhdr: Optional[dict], external_aad: Optional[bytes] = b''):

        super().__init__(phdr, uhdr)

        self.signature = b''
        self._parent_msg = None
        self.external_aad = external_aad

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, value):
        if not isinstance(value, bytes):
            TypeError("Signature must be of type 'bytes'")

        self._signature = value

    @property
    def _sig_structure(self) -> bytes:
        """ Creates the internal sig_structure for a COSE_Signature """

        _sig_structure = [
            self.context,
            self._parent_msg.encode_phdr(),
            self.encode_phdr(),
            self.external_aad,
            self._parent_msg.payload
        ]

        return cbor2.dumps(_sig_structure)

    def encode(self, params: SignerParams) -> list:

        if params.sign:
            message = [self.encode_phdr(),
                       self.encode_uhdr(),
                       self.compute_signature(alg=params.alg, private_key=params.private_key, curve=params.curve)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr()]

        return message

    def __repr__(self) -> str:
        return f'<COSE_Signature: [{self._phdr}, {self._uhdr}, {CoseMessage._truncate(self._signature)}]>'


class CounterSignature(CoseSignature):
    context = "CounterSignature"


class CounterSignature0(CoseSignature):
    context = "CounterSignature0"
