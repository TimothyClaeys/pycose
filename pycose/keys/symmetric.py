from binascii import hexlify
from enum import IntEnum
from typing import Optional, Union

import dataclasses
from dataclasses import dataclass

from pycose.keys.cosekey import CoseKey, KTY


@CoseKey.record_kty(KTY.SYMMETRIC)
@dataclass(init=False)
class SymmetricKey(CoseKey):
    k: Optional[bytes] = None

    class SymPrm(IntEnum):
        K = - 1

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self,
                 kid: Optional[Union[int, bytes]] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 k: Optional[bytes] = None):
        super().__init__(KTY.SYMMETRIC, kid, alg, key_ops, base_iv)
        self.k = k

    @property
    def key_bytes(self):
        return self.k

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> dict:
        """Returns an initialized COSE_Key object."""

        key_obj = super().from_cose_key_obj(cose_key_obj)

        if cls.SymPrm.K in cose_key_obj:
            key_obj[cls.SymPrm.K] = hexlify(key_obj[cls.SymPrm.K])

        return key_obj

    def encode(self, *argv):
        kws = [kw for kw in argv if self.SymPrm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.SymPrm[kw.upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(SymmetricKey)>']
        output.extend(self._base_repr(k, v) if k not in [-1] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)
