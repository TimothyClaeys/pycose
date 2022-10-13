from typing import List, TYPE_CHECKING, Optional, Type, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from pycose.exceptions import CoseInvalidKey, CoseIllegalKeyType, CoseIllegalKeyOps
from pycose.keys.cosekey import CoseKey, KpKty
from pycose.keys.keyparam import (RSAKeyParam, RSAKpN, RSAKpE, RSAKpD, RSAKpP,
                                  RSAKpQ, RSAKpDP, RSAKpDQ, RSAKpQInv, RSAKpOther, RSAKpDi, RSAKpRi, RSAKpTi)
from pycose.keys.keytype import KtyRSA
from pycose.keys.keyops import SignOp, VerifyOp, DeriveKeyOp, DeriveBitsOp

if TYPE_CHECKING:
    from pycose.keys.keyops import KEYOPS
    from pycose.keys.keyparam import KeyParam


@CoseKey.record_kty(KtyRSA)
class RSAKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'RSAKey':
        """
        Returns an initialized COSE Key object of type RSAKey.

        :param cose_key: Dict containing COSE Key parameters and there values.
        :return: an initialized RSAKey key
        """
        _optional_params = {}

        e = CoseKey._extract_from_dict(cose_key, RSAKpE)
        n = CoseKey._extract_from_dict(cose_key, RSAKpN)
        d = CoseKey._extract_from_dict(cose_key, RSAKpD)
        p = CoseKey._extract_from_dict(cose_key, RSAKpP)
        q = CoseKey._extract_from_dict(cose_key, RSAKpQ)
        dp = CoseKey._extract_from_dict(cose_key, RSAKpDP)
        dq = CoseKey._extract_from_dict(cose_key, RSAKpDQ)
        qinv = CoseKey._extract_from_dict(cose_key, RSAKpQInv)
        other = CoseKey._extract_from_dict(cose_key, RSAKpOther, [])
        r_i = CoseKey._extract_from_dict(cose_key, RSAKpRi)
        d_i = CoseKey._extract_from_dict(cose_key, RSAKpDi)
        t_i = CoseKey._extract_from_dict(cose_key, RSAKpTi)

        _optional_params.update(cose_key)
        CoseKey._remove_from_dict(_optional_params, RSAKpE)
        CoseKey._remove_from_dict(_optional_params, RSAKpN)
        CoseKey._remove_from_dict(_optional_params, RSAKpD)
        CoseKey._remove_from_dict(_optional_params, RSAKpP)
        CoseKey._remove_from_dict(_optional_params, RSAKpQ)
        CoseKey._remove_from_dict(_optional_params, RSAKpDP)
        CoseKey._remove_from_dict(_optional_params, RSAKpDQ)
        CoseKey._remove_from_dict(_optional_params, RSAKpQInv)
        CoseKey._remove_from_dict(_optional_params, RSAKpOther)
        CoseKey._remove_from_dict(_optional_params, RSAKpQInv)
        CoseKey._remove_from_dict(_optional_params, RSAKpRi)
        CoseKey._remove_from_dict(_optional_params, RSAKpDi)
        CoseKey._remove_from_dict(_optional_params, RSAKpTi)

        return cls(e=e,
                   n=n,
                   d=d,
                   p=p,
                   q=q,
                   dp=dp,
                   dq=dq,
                   qinv=qinv,
                   other=other,
                   r_i=r_i,
                   d_i=d_i,
                   t_i=t_i,
                   optional_params=_optional_params,
                   allow_unknown_key_attrs=True)

    @staticmethod
    def _key_transform(key: Union[Type['RSAKeyParam'], Type['KeyParam'], str, int], allow_unknown_attrs: bool = False):
        return RSAKeyParam.from_id(key, allow_unknown_attrs)

    def __init__(self,
                 n: bytes = b'',
                 e: bytes = b'',
                 d: bytes = b'',
                 p: bytes = b'',
                 q: bytes = b'',
                 dp: bytes = b'',
                 dq: bytes = b'',
                 qinv: bytes = b'',
                 other: Optional[List[dict]] = None,
                 r_i: bytes = b'',
                 d_i: bytes = b'',
                 t_i: bytes = b'',
                 optional_params: Optional[dict] = None,
                 allow_unknown_key_attrs: bool = True):
        transformed_dict = {KpKty: KtyRSA}

        if other is None:
            other = []

        if optional_params is None:
            optional_params = {}

        # public key, n and e must be defined
        if len(n) != 0 and len(e) != 0 and all(
                map(lambda x: len(x) == 0, [d, p, q, dp, dq, qinv, other, r_i, d_i, t_i])):
            is_valid_key = True

        # private keys with two primes, except other, r_i, t_i and d_i, all other parameters need to be defined
        elif all(map(lambda x: len(x) == 0, [other, r_i, t_i, d_i])) and \
                all(map(lambda x: len(x) != 0, [n, e, d, p, q, dp, dq, qinv])):
            is_valid_key = True

        # private keys with more than two primes, everything needs to be defined
        elif all(map(lambda x: len(x) != 0, [n, e, d, p, q, dp, dq, qinv, other, r_i, d_i, t_i])):
            is_valid_key = True
            # TODO: verify contents of other
        else:
            is_valid_key = False

        if not is_valid_key:
            raise CoseInvalidKey("Invalid RSA key: not a public key, private key with two primes or private key "
                                 "with more than two primes")

        for _key_attribute, _value in optional_params.items():
            # transform the key_attribute
            kp = RSAKeyParam.from_id(_key_attribute, allow_unknown_key_attrs)

            # parse the value of the key attribute if possible
            if hasattr(kp, 'value_parser') and hasattr(kp.value_parser, '__call__'):
                _value = kp.value_parser(_value)

            # store in new dict
            transformed_dict[kp] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtyRSA:
            raise CoseIllegalKeyType(f"Illegal key type in RSA COSE Key: {transformed_dict.get(KpKty)}")

        super(RSAKey, self).__init__(transformed_dict)

        self.e = e
        self.n = n

        if d != b'':
            self.d = d
        if p != b'':
            self.p = p
        if q != b'':
            self.q = q
        if dp != b'':
            self.dp = dp
        if dq != b'':
            self.dq = dq
        if qinv != b'':
            self.qinv = qinv
        if other:
            self.other = other
        if r_i != b'':
            self.r_i = r_i
        if d_i != b'':
            self.d_i = d_i
        if t_i != b'':
            self.t_i = t_i

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
    def dp(self) -> bytes:
        return self.store.get(RSAKpDP, b'')

    @dp.setter
    def dp(self, dp: bytes):
        if type(dp) is not bytes:
            raise TypeError("parameter dp must be of type 'bytes'")
        self.store[RSAKpDP] = dp

    @property
    def dq(self) -> bytes:
        return self.store.get(RSAKpDQ, b'')

    @dq.setter
    def dq(self, dq: bytes):
        if type(dq) is not bytes:
            raise TypeError("parameter dq must be of type 'bytes'")
        self.store[RSAKpDQ] = dq

    @property
    def qinv(self) -> bytes:
        return self.store.get(RSAKpQInv, b'')

    @qinv.setter
    def qinv(self, qinv: bytes):
        if type(qinv) is not bytes:
            raise TypeError("parameter dq must be of type 'bytes'")
        self.store[RSAKpQInv] = qinv

    @property
    def key_ops(self) -> List[Type['KEYOPS']]:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpKeyOps` key parameter """

        return CoseKey.key_ops.fget(self)

    @key_ops.setter
    def key_ops(self, new_key_ops: List[Type['KEYOPS']]) -> None:
        supported = {SignOp, VerifyOp, DeriveKeyOp, DeriveBitsOp}
        for ops in new_key_ops:
            if not self._supported_by_key_type(ops, supported):
                raise CoseIllegalKeyOps(f"Invalid COSE key operation {ops} for key type {RSAKey.__name__}")
            else:
                CoseKey.key_ops.fset(self, new_key_ops)

    @staticmethod
    def generate_key(key_bits: int, optional_params: dict = None) -> 'RSAKey':
        """
        Generate a random RSAKey COSE key object. The RSA keys have two primes (see section 4 of RFC 8230).

        :param key_bits: Specify the number of private key bits.
        :param optional_params: Optional key attribute for the :class:`~pycose.keys.rsa.RSAKey` object.

        :return: An COSE `RSAKey` key.
        """

        key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits, backend=default_backend())

        private_numbers = key.private_numbers()
        p = private_numbers.p.to_bytes((private_numbers.p.bit_length() + 7) // 8, byteorder='big')
        q = private_numbers.q.to_bytes((private_numbers.q.bit_length() + 7) // 8, byteorder='big')
        d = private_numbers.d.to_bytes((private_numbers.d.bit_length() + 7) // 8, byteorder='big')
        dp = private_numbers.dmp1.to_bytes((private_numbers.dmp1.bit_length() + 7) // 8, byteorder='big')
        dq = private_numbers.dmq1.to_bytes((private_numbers.dmq1.bit_length() + 7) // 8, byteorder='big')
        qinv = private_numbers.iqmp.to_bytes((private_numbers.iqmp.bit_length() + 7) // 8, byteorder='big')

        public_numbers = private_numbers.public_numbers

        n = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
        e = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')

        return RSAKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv, optional_params=optional_params)

    def __repr__(self):
        hdr = f'<COSE_Key(RSAKey): {self._key_repr()}>'
        return hdr


RSA = RSAKey
