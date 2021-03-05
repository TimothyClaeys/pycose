from binascii import hexlify
from typing import Optional, List, TYPE_CHECKING, Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cose.exceptions import CoseIllegalAlgorithm
from cose.keys.cosekey import CoseKey, KpKty
from cose.keys.keyparam import (RSAKeyParam, RSAKpN, RSAKpE, RSAKpD, RSAKpP,
                                RSAKpQ, RSAKpDP, RSAKpDQ, RSAKpQInv)
from cose.keys.keytype import KtyRSA

if TYPE_CHECKING:
    from cose.algorithms import CoseAlg
    from cose.keys.cosekey import KEYOPS


def from_bstr(enc):
    return int.from_bytes(enc, byteorder='big')


def to_bstr(dec):
    blen = (dec.bit_length() + 7) // 8
    return dec.to_bytes(blen, byteorder='big')


@CoseKey.record_kty(KtyRSA)
class RSAKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'RSAKey':
        """
        Returns an initialized COSE Key object of type RSAKey.

        :param cose_key: Dict containing COSE Key parameters and there values.
        :return: an initialized RSAKey key
        """

        return cls(cose_key)

    @classmethod
    def from_cryptograpy_key_obj(cls, ext_key) -> 'RSAKey':
        """
        Returns an initialized COSE Key object of type RSAKey.
        :param ext_key: Python cryptography key.
        :return: an initialized RSA key
        """
        if hasattr(ext_key, 'private_numbers'):
            priv_nums = ext_key.private_numbers()
            pub_nums = priv_nums.public_numbers
        else:
            priv_nums = None
            pub_nums = ext_key.public_numbers()

        kwargs = {}
        if pub_nums:
            kwargs.update(dict(
                n=to_bstr(pub_nums.n),
                e=to_bstr(pub_nums.e),
            ))
        if priv_nums:
            kwargs.update(dict(
                p=to_bstr(priv_nums.p),
                q=to_bstr(priv_nums.q),
                d=to_bstr(priv_nums.d),
                dP=to_bstr(priv_nums.dmp1),
                dQ=to_bstr(priv_nums.dmq1),
                qInv=to_bstr(priv_nums.iqmp),
            ))
        return cls(**kwargs)

    def __init__(self, key: Optional[dict]=None, **kwargs):
        transformed_dict = {}
        if key is None:
            key = {}

        new_dict = dict(key, **kwargs)
        new_dict[KpKty] = KtyRSA

        for k, v in new_dict.items():
            try:
                kp = RSAKeyParam.from_id(k)
                if hasattr(kp.value_parser, '__call__'):
                    v = kp.value_parser(v)
                transformed_dict[kp] = v
            except ValueError:
                transformed_dict[k] = v

        super(RSAKey, self).__init__(transformed_dict)

    @property
    def n(self) -> bytes:
        return self.store.get(RSAKpN, b'')

    @n.setter
    def n(self, n: bytes):
        if type(n) is not bytes:
            raise TypeError("parameter n must be of type 'bytes'")
        self.store[RSAKpN] = n

    @property
    def e(self) -> bytes:
        return self.store.get(RSAKpE, b'')

    @e.setter
    def e(self, e: bytes):
        if type(e) is not bytes:
            raise TypeError("parameter e must be of type 'bytes'")
        self.store[RSAKpE] = e

    @property
    def d(self) -> bytes:
        return self.store.get(RSAKpD, b'')

    @d.setter
    def d(self, d: bytes):
        if type(d) is not bytes:
            raise TypeError("parameter d must be of type 'bytes'")
        self.store[RSAKpD] = d

    @property
    def p(self) -> bytes:
        return self.store.get(RSAKpP, b'')

    @p.setter
    def p(self, p: bytes):
        if type(p) is not bytes:
            raise TypeError("parameter p must be of type 'bytes'")
        self.store[RSAKpP] = p

    @property
    def q(self) -> bytes:
        return self.store.get(RSAKpQ, b'')

    @q.setter
    def q(self, q: bytes):
        if type(q) is not bytes:
            raise TypeError("parameter q must be of type 'bytes'")
        self.store[RSAKpQ] = q

    @property
    def dP(self) -> bytes:
        return self.store.get(RSAKpDP, b'')

    @dP.setter
    def dP(self, dp: bytes):
        if type(dp) is not bytes:
            raise TypeError("parameter dp must be of type 'bytes'")
        self.store[RSAKpDP] = dp

    @property
    def dQ(self) -> bytes:
        return self.store.get(RSAKpDQ, b'')

    @dQ.setter
    def dQ(self, dq: bytes):
        if type(dq) is not bytes:
            raise TypeError("parameter dq must be of type 'bytes'")
        self.store[RSAKpDQ] = dq

    @property
    def qInv(self) -> bytes:
        return self.store.get(RSAKpQInv, b'')

    @qInv.setter
    def qInv(self, qinv: bytes):
        if type(qinv) is not bytes:
            raise TypeError("parameter dq must be of type 'bytes'")
        self.store[RSAKpQInv] = qinv

    def verify(self, key_type: Type['RSAKey'], algorithm: Type['CoseAlg'], key_ops: List[Type['KEYOPS']]):
        super(RSAKey, self).verify(key_type, algorithm, key_ops)

        #FIXME: check parameters

    @property
    def is_valid_key(self):
        #FIXME: check parameters
        if self.e == b'' or self.n == b'':
            return False
        return True

    @staticmethod
    def generate_key(key_bits: int) -> 'RSAKey':
        """
        Generate a random RSAKey COSE key object.

        :param key_bits: Specify the number of private key bits.
        :raises CoseIllegalKeyOps: Invalid key operation for this key type.
        :return: An COSE `RSAKey` key.
        """

        ext_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits, backend=default_backend())

        return RSAKey.from_cryptograpy_key_obj(ext_key)

    def __repr__(self):
        hdr = f'<COSE_Key(RSAKey): {self._key_repr()}>'
        return hdr

    def to_cryptograpy_key_obj(self):
        pub_nums = rsa.RSAPublicNumbers(
            e=from_bstr(self.e),
            n=from_bstr(self.n)
        )
        if self.d:
            priv_nums = rsa.RSAPrivateNumbers(
                p=from_bstr(self.p),
                q=from_bstr(self.q),
                d=from_bstr(self.d),
                dmp1=from_bstr(self.dP),
                dmq1=from_bstr(self.dQ),
                iqmp=from_bstr(self.qInv),
                public_numbers=pub_nums
            )
            ext_key = priv_nums.private_key(default_backend())
        else:
            ext_key = pub_nums.public_key(default_backend())

        return ext_key


RSA = RSAKey
