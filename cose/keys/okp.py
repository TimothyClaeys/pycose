from typing import Optional, Type, List, TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, x448, ed25519, ed448
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat, Encoding

from cose.curves import X448, X25519, Ed25519, Ed448, CoseCurve
from cose.exceptions import CoseIllegalCurve, CoseException
from cose.keys.cosekey import CoseKey, KpKty
from cose.keys.keyparam import OKPKeyParam, OKPKpCurve, OKPKpX, OKPKpD
from cose.keys.keytype import KtyOKP

if TYPE_CHECKING:
    from cose.algorithms import CoseAlg
    from cose.keys.keyops import KEYOPS


@CoseKey.record_kty(KtyOKP)
class OKPKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'OKPKey':
        """
        Returns an initialized COSE Key object of type OKPKey.

        :param cose_key: Dict containing COSE Key parameters and there values.
        :return: an initialized OKPKey key
        """

        return cls(cose_key)

    def __init__(self, key: Optional[dict] = None, **kwargs):
        transformed_dict = {}
        if key is None:
            key = {}

        new_dict = dict(key, **kwargs)
        new_dict[KpKty] = KtyOKP

        for k, v in new_dict.items():
            try:
                kp = OKPKeyParam.from_id(k)
                v = v if kp.value_parser is None else kp.value_parser(v)
                transformed_dict[kp] = v
            except ValueError:
                transformed_dict[k] = v

        super(OKPKey, self).__init__(transformed_dict)

    @property
    def crv(self) -> Optional[Type['CoseCurve']]:
        return self.store.get(OKPKpCurve)

    @crv.setter
    def crv(self, crv: Type['CoseCurve']):
        if crv is None:
            return

        self.store[OKPKpCurve] = CoseCurve.from_id(crv)

    @property
    def x(self) -> bytes:
        return self.store.get(OKPKpX, b'')

    @x.setter
    def x(self, x: bytes):
        if type(x) is not bytes:
            raise TypeError("public x coordinate must be of type 'bytes'")
        self.store[OKPKpX] = x

    @property
    def d(self) -> bytes:
        return self.store.get(OKPKpD, b'')

    @d.setter
    def d(self, d: bytes):
        if type(d) is not bytes:
            raise TypeError("private key must be of type 'bytes'")
        self.store[OKPKpD] = d

    def verify(self, key_type: Type['OKPKey'], algorithm: Type['CoseAlg'], key_ops: List[Type['KEYOPS']]):
        super(OKPKey, self).verify(key_type, algorithm, key_ops)

        if self.crv is None:
            raise CoseException("Curve attribute cannot be None.")

    @property
    def is_valid_key(self):

        if self.crv == X25519:
            if self.d != b'':
                _ = x25519.X25519PrivateKey.from_private_bytes(self.d)
            if self.x != b'':
                _ = x25519.X25519PublicKey.from_public_bytes(self.x)
        elif self.crv == X448:
            if self.d != b'':
                _ = x448.X448PrivateKey.from_private_bytes(self.d)
            if self.x != b'':
                _ = x448.X448PublicKey.from_public_bytes(self.x)
        elif self.crv == Ed25519:
            if self.d != b'':
                _ = ed25519.Ed25519PrivateKey.from_private_bytes(self.d)
            if self.x != b'':
                _ = ed25519.Ed25519PublicKey.from_public_bytes(self.x)
        elif self.crv == Ed448:
            if self.d != b'':
                _ = ed448.Ed448PrivateKey.from_private_bytes(self.d)
            if self.x != b'':
                _ = ed448.Ed448PublicKey.from_public_bytes(self.x)
        else:
            return False

        return True

    @staticmethod
    def generate_key(curve: Type['CoseCurve']) -> 'OKPKey':
        """
        Generate a random OKPKey COSE key object.

        :param curve: Specify an elliptic curve.
        :raises CoseIllegalCurve: Invalid curve for this key type.
        :raises CoseIllegalKeyOps: Invalid key operation for this key type.
        :returns: An COSE `OKPKey` key.
        """

        if curve == X25519:
            private_key = X25519PrivateKey.generate()
        elif curve == Ed25519:
            private_key = Ed25519PrivateKey.generate()
        elif curve == Ed448:
            private_key = Ed448PrivateKey.generate()
        elif curve == X448:
            private_key = X448PrivateKey.generate()
        else:
            raise CoseIllegalCurve(f"Curve must be of type {X25519} or {X448}")

        encoding = Encoding(serialization.Encoding.Raw)
        private_format = PrivateFormat(serialization.PrivateFormat.Raw)
        public_format = PublicFormat(serialization.PublicFormat.Raw)
        encryption = serialization.NoEncryption()

        return OKPKey(
            curve=curve,
            x=private_key.public_key().public_bytes(encoding, public_format),
            d=private_key.private_bytes(encoding, private_format, encryption))

    def __repr__(self):
        hdr = f'<COSE_Key(OKPKey): {self._key_repr()}>'
        return hdr


OKPKpCurve.value_parser = CoseCurve.from_id

OKP = OKPKey
