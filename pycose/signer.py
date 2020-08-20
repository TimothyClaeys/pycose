from typing import Optional, Union, TYPE_CHECKING

import cbor2
from dataclasses import dataclass

from pycose import signcommon
from pycose.algorithms import AlgorithmIDs
from pycose.keys.cosekey import EllipticCurveTypes
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP

if TYPE_CHECKING:
    from pycose.signmessage import SignMessage


@dataclass
class SignerParams:
    private_key: Union[EC2, OKP]
    alg: Optional[AlgorithmIDs] = None
    curve: Optional[EllipticCurveTypes] = None
    sign: bool = True


class CoseSignature(signcommon.SignCommon):
    context = "Signature"

    @classmethod
    def from_signature_obj(cls, cose_signature_obj: list, encaps_msg: 'SignMessage'):
        msg = super().from_cose_obj(cose_signature_obj)
        msg.signature = cose_signature_obj.pop()
        msg.encaps_msg = encaps_msg
        return msg

    def __init__(self,
                 phdr: Optional[dict],
                 uhdr: Optional[dict],
                 signature: Optional[bytes] = b'',
                 external_aad: Optional[bytes] = b'',
                 encaps_msg: Optional['SignMessage'] = None):

        super().__init__(phdr, uhdr, external_aad=external_aad)

        self.signature = signature
        self.encaps_msg = encaps_msg

    @property
    def _sig_structure(self) -> bytes:
        """ Creates the internal sig_structure for a COSE_Signature """

        _sig_structure = [
            self.context,
            self.encaps_msg.encode_phdr(),
            self.encode_phdr(),
            self.external_aad,
            self.payload
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
        pass


class CounterSignature(CoseSignature):
    context = "CounterSignature"


class CounterSignature0(CoseSignature):
    context = "CounterSignature0"
