from binascii import hexlify
from typing import Optional, List, TYPE_CHECKING, Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1
from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST384p, NIST521p
from ecdsa.ellipticcurve import Point

from cose.curves import CoseCurve, P256, P521, P384
from cose.exceptions import CoseIllegalCurve, CoseException
from cose.keys.cosekey import CoseKey, KpKty
from cose.keys.keyparam import EC2KeyParam, EC2KpCurve, EC2KpX, EC2KpY, EC2KpD
from cose.keys.keytype import KtyEC2

if TYPE_CHECKING:
    from cose.algorithms import CoseAlg
    from cose.keys.cosekey import KEYOPS


@CoseKey.record_kty(KtyEC2)
class EC2Key(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'EC2Key':
        """
        Returns an initialized COSE Key object of type EC2Key.

        :param cose_key: Dict containing COSE Key parameters and there values.
        :return: an initialized EC2Key key
        """

        return cls(cose_key)

    def __init__(self, key: Optional[dict] = None, **kwargs):
        transformed_dict = {}
        if key is None:
            key = {}

        new_dict = dict(key, **kwargs)
        new_dict[KpKty] = KtyEC2

        for k, v in new_dict.items():
            try:
                kp = EC2KeyParam.from_id(k)
                if hasattr(kp.value_parser, '__call__'):
                    v = kp.value_parser(v)
                transformed_dict[kp] = v
            except ValueError:
                transformed_dict[k] = v

        super(EC2Key, self).__init__(transformed_dict)

    @property
    def crv(self) -> Optional[Type[CoseCurve]]:
        return self.store.get(EC2KpCurve)

    @crv.setter
    def crv(self, crv: Type[CoseCurve]):
        if crv is None:
            return

        self.store[EC2KpCurve] = CoseCurve.from_id(crv)

    @property
    def x(self) -> bytes:
        return self.store.get(EC2KpX, b'')

    @x.setter
    def x(self, x: bytes):
        if type(x) is not bytes:
            raise TypeError("public x coordinate must be of type 'bytes'")
        self.store[EC2KpX] = x

    @property
    def y(self) -> bytes:
        return self.store.get(EC2KpY, b'')

    @y.setter
    def y(self, y: bytes):
        if type(y) is not bytes:
            raise TypeError("public y coordinate must be of type 'bytes'")
        self.store[EC2KpY] = y

    @property
    def d(self) -> bytes:
        return self.store.get(EC2KpD, b'')

    @d.setter
    def d(self, d: bytes):
        if type(d) is not bytes:
            raise TypeError("private key must be of type 'bytes'")
        self.store[EC2KpD] = d

    def verify(self, key_type: Type['EC2Key'], algorithm: Type['CoseAlg'], key_ops: List[Type['KEYOPS']]):
        super(EC2Key, self).verify(key_type, algorithm, key_ops)

        if self.crv is None:
            raise CoseException("Curve attribute cannot be None.")

    @property
    def is_valid_key(self):

        if self.crv == P256:
            curve = NIST256p
        elif self.crv == P384:
            curve = NIST384p
        elif self.crv == P521:
            curve = NIST521p
        else:
            raise CoseIllegalCurve()

        if self.d != b'':
            _ = SigningKey.from_secret_exponent(int(hexlify(self.d), 16), curve=curve)

        if self.x or self.y:
            p = Point(curve=curve.curve, x=int(hexlify(self.x), 16), y=int(hexlify(self.y), 16))
            _ = VerifyingKey.from_public_point(p, curve, validate_point=True)

        return True

    @staticmethod
    def generate_key(curve: Type[CoseCurve]) -> 'EC2Key':
        """
        Generate a random EC2Key COSE key object.

        :param curve: Specify an :class:`~cose.attributes.algorithms.CoseEllipticCurves`.
        :raises CoseIllegalCurve: Invalid curves for this key type.
        :raises CoseIllegalKeyOps: Invalid key operation for this key type.
        :return: An COSE `EC2Key` key.
        """
        if curve == P256:
            curve_obj = SECP256R1()
        elif curve == P384:
            curve_obj = SECP384R1()
        elif curve == P521:
            curve_obj = SECP521R1()
        else:
            raise CoseIllegalCurve()

        private_key = ec.generate_private_key(curve_obj, backend=default_backend())
        d_value = private_key.private_numbers().private_value
        x_coor = private_key.public_key().public_numbers().x
        y_coor = private_key.public_key().public_numbers().y

        return EC2Key(
            curve=curve,
            d=d_value.to_bytes((d_value.bit_length() + 7) // 8, byteorder="big"),
            x=x_coor.to_bytes((x_coor.bit_length() + 7) // 8, byteorder="big"),
            y=y_coor.to_bytes((y_coor.bit_length() + 7) // 8, byteorder="big"))

    def __repr__(self):
        hdr = f'<COSE_Key(EC2Key): {self._key_repr()}>'
        return hdr


EC2KpCurve.value_parser = CoseCurve.from_id

EC2 = EC2Key
