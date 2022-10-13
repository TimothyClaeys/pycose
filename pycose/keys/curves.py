from abc import ABC, abstractmethod
from typing import Union

from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve, SECP256K1, SECP256R1, SECP384R1, SECP521R1

from pycose.keys.keytype import KtyEC2, KtyOKP
from pycose.utils import _CoseAttribute

EdwardsCurve = Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]


class CoseCurve(_CoseAttribute, ABC):
    """ Base class for all COSE curves. """

    _registered_curves = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_curves

    @property
    @abstractmethod
    def curve_obj(self) -> Union[EllipticCurve, 'EdwardsCurve']:
        """
        Returns a curve object from the cryptography package
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def key_type(self) -> Union['KtyEC2', 'KtyOKP']:
        """
        Returns the key type associated with the curve
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def size(self) -> int:
        """
        Returns the size of the coordinates over the curve
        """
        raise NotImplementedError()


##################################################
#            SUPPORTED COSE CURVES               #
##################################################


@CoseCurve.register_attribute()
class Reserved(CoseCurve):
    """
    Reserved

    Attributes:
        **identifier**     *0*

        **fullname**       *RESERVED*

        **curve_obj**      *None*

        **key_type**       *None*

        **size**           *0*
    """

    identifier = 0
    fullname = "RESERVED"
    curve_obj = None
    key_type = None
    size = 0


@CoseCurve.register_attribute()
class P256(CoseCurve):
    """
    Curve NIST P-256

    Attributes:
        **identifier**     *1*

        **fullname**       *P_256*

        **curve_obj**      *SECP256R1 from the cryptography package*

        **key_type**       *KtyEC2*

        **size**           *32*
    """

    identifier = 1
    fullname = "P_256"
    curve_obj = SECP256R1
    key_type = KtyEC2
    size = 32


@CoseCurve.register_attribute()
class P384(CoseCurve):
    """
    Curve NIST P-384

    Attributes:
        **identifier**     *2*

        **fullname**       *P_384*

        **curve_obj**      *SECP384R1 from the cryptography package*

        **key_type**       *KtyEC2*

        **size**           *48*
    """

    identifier = 2
    fullname = "P_384"
    curve_obj = SECP384R1
    key_type = KtyEC2
    size = 48


@CoseCurve.register_attribute()
class P521(CoseCurve):
    """
    Curve NIST P-521

    Attributes:
        **identifier**     *3*

        **fullname**       *P_521*

        **curve_obj**      *SECP521R1 from the cryptography package*

        **key_type**       *KtyEC2*

        **size**           *66*
    """

    identifier = 3
    fullname = "P_521"
    curve_obj = SECP521R1
    key_type = KtyEC2
    size = 66


@CoseCurve.register_attribute()
class X25519(CoseCurve):
    """
    Curve25519 for the Diffie-Hellman function (X25519)

    Attributes:
        **identifier**     *4*

        **fullname**       *X25519*

        **curve_obj**      *X25519PrivateKey from the cryptography package*

        **key_type**       *KtyOKP*

        **size**           *32*
    """

    identifier = 4
    fullname = "X25519"
    curve_obj = x25519.X25519PrivateKey
    key_type = KtyOKP
    size = 32


@CoseCurve.register_attribute()
class X448(CoseCurve):
    """
    Curve448 for the Diffie-Hellman function (X448)

    Attributes:
        **identifier**     *5*

        **fullname**       *X448*

        **curve_obj**      *X25519PrivateKey from the cryptography package*

        **key_type**       *KtyOKP*

        **size**           *57*
    """

    identifier = 5
    fullname = "X448"
    curve_obj = x448.X448PrivateKey
    key_type = KtyOKP
    size = 57


@CoseCurve.register_attribute()
class Ed25519(CoseCurve):
    """
    Curve25519 for the EdDSA algorithm (Ed25519)

    Attributes:
        **identifier**     *6*

        **fullname**       *ED25519*

        **curve_obj**      *Ed25519PrivateKey from the cryptography package*

        **key_type**       *KtyOKP*

        **size**           *32*
    """

    identifier = 6
    fullname = "ED25519"
    curve_obj = ed25519.Ed25519PrivateKey
    key_type = KtyOKP
    size = 32


@CoseCurve.register_attribute()
class Ed448(CoseCurve):
    """
    Curve448 for the EdDSA algorithm (Ed448)

    Attributes:
        **identifier**     *7*

        **fullname**       *ED448*

        **curve_obj**      *Ed448PrivateKey from the cryptography package*

        **key_type**       *KtyOKP*

        **size**           *57*
    """

    identifier = 7
    fullname = "ED448"
    curve_obj = ed448.Ed448PrivateKey
    key_type = KtyOKP
    size = 57


@CoseCurve.register_attribute()
class SECP256K1(CoseCurve):
    """
    Curve secp256k1

    Attributes:
        **identifier**     *8*

        **fullname**       *SECP256K1*

        **curve_obj**      *SECP256K1 from the cryptography package*

        **key_type**       *KtyEC2*

        **size**           *32*
    """

    identifier = 8
    fullname = "SECP256K1"
    curve_obj = SECP256K1
    key_type = KtyEC2
    size = 32


if __name__ == '__main__':
    print(CoseCurve.get_registered_classes())
