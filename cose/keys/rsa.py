from binascii import hexlify
from typing import Optional, List, TYPE_CHECKING, Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cose.exceptions import CoseIllegalKeyType, CoseInvalidKey
from cose.keys.cosekey import CoseKey, KeyParam, KpKty
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

#: Map from kwarg key to parameter object
PARAM = {
    'e': RSAKpE,
    'n': RSAKpN,
    'd': RSAKpD,
    'p': RSAKpP,
    'q': RSAKpQ,
    'dp': RSAKpDP,
    'dq': RSAKpDQ,
    'qinv': RSAKpQInv,
}


@CoseKey.record_kty(KtyRSA)
class RSAKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'RSAKey':
        """
        Returns an initialized COSE Key object of type RSAKey.

        :param cose_key: Dict containing COSE Key parameters and there values.
        :return: an initialized RSAKey key
        """

        kwargs = {}

        for (attr, kob) in RSAKey.PARAM.items():
            if kob in cose_key:
                val = cose_key[kob]
            elif kob.identifier in cose_key:
                val = cose_key[kob.identifier]
            elif kob.fullname in cose_key:
                val = cose_key[kob.fullname]
            else:
                val = b''
            kwargs[attr] = val

        kwargs['optional_params'] = cose_key
        return cls(**kwargs)

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

        cose_key = {}
        if pub_nums:
            cose_key.update({
                RSAKpE: to_bstr(pub_nums.e),
                RSAKpN: to_bstr(pub_nums.n),
            })
        if priv_nums:
            cose_key.update({
                RSAKpD: to_bstr(priv_nums.d),
                RSAKpP: to_bstr(priv_nums.p),
                RSAKpQ: to_bstr(priv_nums.q),
                RSAKpDP: to_bstr(priv_nums.dmp1),
                RSAKpDQ: to_bstr(priv_nums.dmq1),
                RSAKpQInv: to_bstr(priv_nums.iqmp),
            })
        return RSAKey.from_dict(cose_key)

    def __init__(self, e: bytes=b'', n: bytes=b'',
                 d: bytes=b'', p: bytes=b'', q: bytes=b'',
                 dp: bytes=b'', dq: bytes=b'', qinv: bytes=b'',
                 optional_params: Optional[dict]=None):
        transformed_dict = {}

        if len(e) == 0 and len(n) == 0:
            raise CoseInvalidKey("Either the public values or the private value must be specified")

        new_dict = dict({KpKty: KtyRSA, RSAKpE: e, RSAKpN: n})
        if len(d) != 0:
            new_dict.update({RSAKpD: d})
        if len(p) != 0:
            new_dict.update({RSAKpP: p})
        if len(q) != 0:
            new_dict.update({RSAKpQ: q})
        if len(dp) != 0:
            new_dict.update({RSAKpDP: dp})
        if len(dq) != 0:
            new_dict.update({RSAKpDQ: dq})
        if len(qinv) != 0:
            new_dict.update({RSAKpQInv: qinv})

        if optional_params is not None:
            new_dict.update(optional_params)

        for _key_attribute, _value in new_dict.items():
            try:
                # translate the key_attribute
                kp = RSAKeyParam.from_id(_key_attribute)

                # parse the value of the key attribute if possible
                if hasattr(kp.value_parser, '__call__'):
                    _value = kp.value_parser(_value)

                # store in new dict
                transformed_dict[kp] = _value
            except ValueError:
                transformed_dict[_key_attribute] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtyRSA:
            raise CoseIllegalKeyType(f"Illegal key type in RSA COSE Key: {transformed_dict.get(KpKty)}")

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

    @property
    def is_valid_key(self):
        pub_attrs = {'e', 'n'}
        priv_attrs = {'d', 'p', 'q', 'dP', 'dQ', 'qInv'}

        pub_set = [bool(getattr(self, name)) for name in pub_attrs]
        priv_set = [bool(getattr(self, name)) for name in priv_attrs]
        if not all(pub_set):
            return False
        if any(priv_set) and not all(priv_set):
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
        ''' Get the `crypographic` library representation of this key.
        :return: An :py:cls:`RSAPublicKey` or :py:cls:`RSAPrivateKey` object.
        '''
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
