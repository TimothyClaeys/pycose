from typing import Optional, Union, Tuple

import cbor2

from pycose import cosemessage, crypto
from pycose.attributes import CoseAlgorithm, CoseHeaderParam
from pycose.cosekey import EC2, OKP


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
                 key: Optional[Union[EC2, OKP]] = None):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key)

        self.signature = b''

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

    def verify_signature(self, alg: Optional[CoseAlgorithm] = None, key: Optional[Union[EC2, OKP]] = None) -> bool:
        """
        Verifies the signature of a received message
        :return: True or raises an exception
        """
        _alg, _key = self._get_crypt_params(alg, key)

        return crypto.ec_verify_wrapper(_key, self._sig_structure, self.signature, _alg)

    def compute_signature(self,
                          alg: Optional[CoseAlgorithm] = None,
                          key: Optional[Union[EC2, OKP]] = None):

        to_sign = self._sig_structure

        _alg, _key = self._get_crypt_params(alg, key)
        return crypto.ec_sign_wrapper(_key, to_sign, _alg)

    def encode(self,
               tagged: bool = True,
               sign: bool = True,
               alg: Optional[CoseAlgorithm] = None,
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

    def _get_crypt_params(self,
                          alg: Optional[CoseAlgorithm],
                          key: Optional[Union[EC2, OKP]]) -> Tuple[CoseAlgorithm, Union[EC2, OKP]]:

        # if nothing is overridden by the function parameters, search in COSE headers
        _alg = alg if alg is not None else self.phdr.get(CoseHeaderParam.ALG)
        _alg = _alg if _alg is not None else self.uhdr.get(CoseHeaderParam.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        try:
            _key = key if key is not None else self.key
        except AttributeError:
            raise AttributeError("No key specified.")

        return _alg, _key

    def __repr__(self):
        return f'<COSE_Sign1:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t signature={self.signature}>'
