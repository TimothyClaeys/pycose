from typing import Optional, TYPE_CHECKING, Union, TypeVar

import cbor2

from pycose import utils
from pycose.messages.signcommon import SignCommon
from pycose.exceptions import CoseException

if TYPE_CHECKING:
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA


class CoseSignature(SignCommon):
    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool) -> 'CoseSignature':
        """ Parses COSE_Signature objects. """

        msg: 'CoseSignature' = super().from_cose_obj(cose_obj, allow_unknown_attributes)

        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 signature: bytes = b'',
                 external_aad: Optional[bytes] = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload=signature, external_aad=external_aad, key=key, *args, **kwargs)

        self._parent = None

    @property
    def cbor_tag(self):
        return None

    @property
    def signature(self):
        return self._payload

    @signature.setter
    def signature(self, value):
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")

        self._payload = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None):
        sign_structure = [self._parent.context, self._parent.phdr_encoded]

        if len(self.phdr):
            sign_structure.append(self.phdr_encoded)

        sign_structure.append(self.external_aad)

        if detached_payload is None:
            if self._parent.payload is None:
                raise CoseException("Missing payload and no detached payload provided")
            sign_structure.append(self._parent.payload)
        else:
            if self._parent.payload is not None:
                raise CoseException("Detached payload must be None when payload is set")
            sign_structure.append(detached_payload)

        aad = cbor2.dumps(sign_structure)
        return aad

    def encode(self, detached_payload: Optional[bytes] = None, *args, **kwargs) -> list:
        return [self.phdr_encoded, self.uhdr_encoded, self.compute_signature(detached_payload)]

    def __repr__(self) -> str:
        return f'<COSE_Signature: [{self._phdr}, {self._uhdr}, {utils.truncate(self._payload)}]>'


Signer = TypeVar('Signer', bound=CoseSignature)
