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

from pycose import cosemessage, crypto
from pycose.attributes import CoseAlgorithm, CoseHeaderParam
from pycose.cosekey import OKP, EC2
from pycose.cosesignature import CoseSignature


@cosemessage.CoseMessage.record_cbor_tag(98)
class SignMessage(cosemessage.CoseMessage):
    cbor_tag = 98
    context = "Signature"

    @classmethod
    def from_cose_obj(cls, cose_obj):
        msg = super().from_cose_obj(cose_obj)

        msg.cose_signatures = [CoseSignature.from_signature_obj(r) for r in cose_obj.pop(0)]
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

        super().__init__(phdr, uhdr, payload, b'', None)

        if cose_signatures is None:
            self.cose_signatures = list()
        else:
            self.cose_signatures = cose_signatures

    def _sig_structure(self, cose_signature):
        _sig_structure = [
            cose_signature.context,
            self.encode_phdr(),
            cose_signature.encode_phdr(),
            cose_signature.external_aad,
            self.payload
        ]

        return cbor2.dumps(_sig_structure)

    def verify_signature(self,
                         cose_signature: Optional[CoseSignature],
                         alg: Optional[CoseAlgorithm] = None,
                         key: Optional[Union[EC2, OKP]] = None) -> bool:

        _alg, _key = SignMessage._get_crypt_params(cose_signature, alg, key)

        return crypto.ec_verify_wrapper(_key, self._sig_structure(cose_signature), cose_signature.signature, _alg)

    def encode(self,
               tagged: bool = True,
               alg: Optional[CoseAlgorithm] = None,
               key: Optional[Union[EC2, OKP]] = None,
               sign_params: Tuple[Tuple[bool, Optional[CoseAlgorithm], Optional[Union[EC2, OKP]]]] = None) -> bytes:
        """ Encodes the message as a CBOR array """

        if sign_params is None:
            sign_params = ((True, None, None),)

        message = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        if len(sign_params) > len(self.cose_signatures):
            raise ValueError("sign_params to long")

        signers = list()
        for cose_signature, param in zip_longest(self.cose_signatures, sign_params, fillvalue=((True, None, None),)):
            sign, alg, key = param
            _alg, _key = SignMessage._get_crypt_params(cose_signature, alg, key)

            if sign:
                signature = CoseSignature.compute_signature(self._sig_structure(cose_signature), _alg, _key)
            else:
                signature = None

            signers.append(cose_signature.encode(signature))

        message.append(signers)

        if tagged:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message))
        else:
            message = cbor2.dumps(message)

        return message

    @classmethod
    def _get_crypt_params(cls,
                          cose_signature: Optional[CoseSignature],
                          alg: Optional[CoseAlgorithm],
                          key: Optional[Union[EC2, OKP]]) -> Tuple[CoseAlgorithm, Union[EC2, OKP]]:

        try:
            _key = key if key is not None else cose_signature.key
        except AttributeError:
            raise AttributeError("No key specified.")

        _alg = alg if alg is not None else cose_signature.phdr.get(CoseHeaderParam.ALG)
        _alg = _alg if _alg is not None else cose_signature.uhdr.get(CoseHeaderParam.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        return _alg, _key

    def __repr__(self):
        return f'<COSE_Sign:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t signatures={self.cose_signatures}>'
