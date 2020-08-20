# CDDL fragment MACed Message with Recipients
#
# COSE_Sign = [
#    Headers,
#    payload: bstr / nil,
#    signatures: [+ COSE_Signature]
# ]
#
from typing import Optional, Union, List

import cbor2

from pycose import cosemessage
from pycose.algorithms import AlgorithmIDs
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP
from pycose.signer import CoseSignature, SignerParams


@cosemessage.CoseMessage.record_cbor_tag(98)
class SignMessage(cosemessage.CoseMessage):
    cbor_tag = 98

    @classmethod
    def from_cose_obj(cls, cose_obj) -> 'SignMessage':
        msg = super().from_cose_obj(cose_obj)

        msg.cose_signatures = [CoseSignature.from_signature_obj(r, msg) for r in cose_obj.pop(0)]
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 cose_signatures: Optional[List[CoseSignature]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, payload)

        if cose_signatures is None:
            self.cose_signatures = list()
        else:
            self.cose_signatures = cose_signatures

    def encode(self,
               key: Union[EC2, OKP],
               alg: Optional[AlgorithmIDs] = None,
               sign_params: Optional[List[SignerParams]] = None,
               tagged: bool = True) -> bytes:
        """ Encodes and protects the COSE_Sign message."""

        signers = []
        message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if sign_params is None:
            sign_params = []

        if len(sign_params) == len(self.cose_signatures):
            for cose_signature, p in zip(self.cose_signatures, sign_params):
                signers.append(cose_signature.encode(p))
        else:
            raise ValueError("List with cryptographic parameters should have the same length as the recipient list.")

        message.append(signers)

        if tagged:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message))
        else:
            message = cbor2.dumps(message)

        return message

    def __repr__(self):
        return f'<COSE_Sign:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t signatures={self.cose_signatures}>'
