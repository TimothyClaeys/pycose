from typing import Union, List

import cbor2

from pycose.attributes import CoseHeaderParam
from pycose.basicstructure import BasicCoseStructure
from pycose.cosekey import SymmetricKey
from pycose.crypto import key_wrap


class CoseRecipient(BasicCoseStructure):

    def __init__(self, phdr: Union[dict, None] = None,
                 uhdr: Union[dict, None] = None,
                 payload: bytes = b'',
                 wrapping_key: SymmetricKey = None,
                 recipients: Union[List, None] = None):
        super().__init__(phdr=phdr, uhdr=uhdr, payload=payload)

        self.wrapping_key = wrapping_key
        self.recipients = recipients

    def encode(self):
        if self.recipients is not None:
            res = cbor2.dumps(
                [self.encode_phdr(), self.encode_uhdr(), self.payload, [r.encode() for r in self.recipients]])
        else:
            res = cbor2.dumps([self.encode_phdr(), self.encode_uhdr(), self.payload])

        return res

    def encrypt(self, alg: int = None) -> bytes:
        """ Do key wrapping. """

        if self.wrapping_key is None:
            raise AttributeError('No key specified')

        # search in protected headers
        _alg = self.phdr.get(CoseHeaderParam.ALG) if alg is None else alg

        # search in unprotected headers
        _alg = self.uhdr.get(CoseHeaderParam.ALG) if _alg is None else _alg

        if _alg is None:
            raise AttributeError('No algorithm specified')

        return key_wrap(_alg, self.wrapping_key, self.payload)

    @classmethod
    def derive_wrapping_key(cls, context: bytes = b'', salt: bytes = b'', private_key: bytes = None,
                            public_key: bytes = None, symmetric_key: bytes = None):
        pass


    def __repr__(self) -> str:
        return f'<COSE_Recipient:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t recipients={self.recipients}>'
