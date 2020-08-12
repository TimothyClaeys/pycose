# CDDL fragment MACed Message with Recipients
#
# COSE_Sign = [
#    Headers,
#    payload: bstr / nil,
#    signatures: [+ COSE_Signature]
# ]
#
from itertools import zip_longest
from typing import Optional, Union, List, Tuple

import cbor2
from cbor2 import CBORDecodeEOF

from pycose import cosemessage
from pycose.attributes import CoseAlgorithm
from pycose.basicstructure import BasicCoseStructure
from pycose.cosekey import OKP, EC2
from pycose.sign1message import Sign1Message


class CoseSignature(Sign1Message):
    context = "Signature"

    @classmethod
    def from_signature_obj(cls, signature_list: list, msg: 'SignMessage'):

        try:
            phdr = BasicCoseStructure.parse_cose_hdr(cbor2.loads(signature_list.pop(0)))
        except (IndexError, CBORDecodeEOF):
            phdr = {}

        try:
            uhdr = BasicCoseStructure.parse_cose_hdr(signature_list.pop(0))
        except IndexError:
            uhdr = {}

        try:
            signature = signature_list.pop(0)
        except IndexError:
            signature = None

        return CoseSignature(msg, phdr, uhdr, signature)

    def __init__(self,
                 cose_sign_msg: 'SignMessage',
                 phdr: Optional[dict],
                 uhdr: Optional[dict],
                 signature: Optional[bytes] = b'',
                 external_aad: Optional[bytes] = b'',
                 key: Optional[Union[EC2, OKP]] = None):
        super().__init__(phdr=phdr, uhdr=uhdr, payload=b'', external_aad=external_aad, key=key)
        self.cose_sign_msg = cose_sign_msg
        self.signature = signature

    def encode(self,
               sign: bool = True,
               alg: Optional[CoseAlgorithm] = None,
               key: Optional[Union[EC2, OKP]] = None, **kwargs) -> list:

        if sign:
            message = [self.encode_phdr(), self.encode_uhdr(), self.compute_signature(alg, key)]
        else:
            message = [self.encode_phdr(), self.encode_uhdr()]

        # tagging is not supported for COSE_signature objects
        return message

    @property
    def _sig_structure(self):
        """
        create the sig_structure that needs to be signed
        :return: to_be_signed
        """
        sig_structure = [
            self.context,
            self.cose_sign_msg.encode_phdr(),
            self.encode_phdr(),
            self._external_aad,
            self.cose_sign_msg.payload
        ]

        return cbor2.dumps(sig_structure)


class CounterSignature(CoseSignature):
    context = "CounterSignature"


@cosemessage.CoseMessage.record_cbor_tag(98)
class SignMessage(cosemessage.CoseMessage):
    cbor_tag = 98

    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super().from_cose_obj(cose_obj)

        msg.signatures = [CoseSignature.from_signature_obj(r, msg) for r in cose_obj.pop(0)]
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 signatures: Optional[List[CoseSignature]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, b'', None)

        if signatures is None:
            self.signatures = list()
        else:
            self.signatures = signatures

    def encode(self,
               tagged: bool = True,
               alg: Optional[CoseAlgorithm] = None,
               key: Optional[Union[EC2, OKP]] = None,
               sign_params: Tuple[Tuple[bool, Optional[CoseAlgorithm], Optional[Union[EC2, OKP]]]] = None) -> bytes:
        """ Encodes the message as a CBOR array """

        if sign_params is None:
            sign_params = ((True, None, None),)

        message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if len(sign_params) > len(self.signatures):
            raise ValueError("sign_params to long")

        signers = list()
        for signature, param in zip_longest(self.signatures, sign_params, fillvalue=((True, None, None),)):
            signers.append(signature.encode(*param))

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
               f'\t signatures={self.signatures}>'

    @property
    def context(self) -> str:
        raise NotImplementedError
