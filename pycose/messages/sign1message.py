from typing import Optional, Union, TYPE_CHECKING

import cbor2

from pycose import utils
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.signcommon import SignCommon
from pycose.exceptions import CoseException

if TYPE_CHECKING:
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA

CBOR = bytes


@CoseMessage.record_cbor_tag(18)
class Sign1Message(SignCommon):
    context = "Signature1"
    cbor_tag = 18

    @classmethod
    def from_cose_obj(cls, cose_obj, allow_unknown_attributes: bool) -> 'Sign1Message':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg._signature = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: Optional[bytes] = None,
                 external_aad: bytes = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

        self._signature = b''

    @property
    def signature(self):
        return self._signature
    
    @signature.setter
    def signature(self, value):
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")

        self._signature = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None):
        """
        Create the sig_structure that needs to be signed

        :return: to_be_signed
        """
        sig_structure = [self.context]
        sig_structure = self._base_structure(sig_structure)

        if detached_payload is None:
            if self.payload is None:
                raise CoseException("Missing payload and no detached payload provided")
            sig_structure.append(self.payload)
        else:
            if self.payload is not None:
                raise CoseException("Detached payload must be None when payload is set")
            sig_structure.append(detached_payload)

        return cbor2.dumps(sig_structure)

    def encode(self, tag: bool = True, sign: bool = True, detached_payload: Optional[bytes] = None, *args, **kwargs) -> CBOR:
        """ Encodes the message into a CBOR array with or without a CBOR tag. """

        if sign:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.compute_signature(detached_payload)]
        elif self.signature:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.signature]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        if tag:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)
        else:
            res = cbor2.dumps(message, default=self._custom_cbor_encoder)

        return res

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Sign1: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, ' \
               f'{utils.truncate(self._signature)}]>'
