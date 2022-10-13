# COSE_Sign = [
#    Headers,
#    payload: bstr / nil,
#    signatures: [+ COSE_Signature]
# ]

import abc
from typing import Optional, List, TYPE_CHECKING

import cbor2

from pycose import utils
from pycose.exceptions import CoseException
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.signer import CoseSignature

if TYPE_CHECKING:
    from pycose.messages.signer import Signer


class _SignMessage(CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """ Getter for the context of the message. """
        raise NotImplementedError

    @classmethod
    def from_cose_obj(cls, cose_obj, allow_unknown_attributes: bool) -> '_SignMessage':
        """ Parses COSE_Sign messages. """

        msg: '_SignMessage' = super().from_cose_obj(cose_obj, allow_unknown_attributes)

        signers = []
        for r in cose_obj.pop(0):
            signers.append(CoseSignature.from_cose_obj(r, allow_unknown_attributes))

        msg.signers = signers
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 signers: Optional[List['Signer']] = None,
                 *args,
                 **kwargs):

        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super(_SignMessage, self).__init__(phdr, uhdr, payload, external_aad=b'', key=None, *args, **kwargs)

        if signers is None:
            self._signers = list()
        else:
            self.signers = signers

    @property
    def signers(self):
        return self._signers

    @signers.setter
    def signers(self, signers: List['Signer']):
        if isinstance(signers, list):
            for s in signers:
                s._parent = self
            self._signers = signers
        else:
            raise CoseException("Signers must be of type list")

    def encode(self, tag: bool = True, *args, **kwargs) -> bytes:
        """ Encodes and protects the COSE_Sign message. """

        message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        if len(self.signers):
            message.append([s.encode() for s in self.signers])

        if tag:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)
        else:
            message = cbor2.dumps(message, default=self._custom_cbor_encoder)

        return message

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Sign: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, {self._signers}]>'


@CoseMessage.record_cbor_tag(98)
class SignMessage(_SignMessage):
    cbor_tag = 98
    context = "Signature"
