from abc import ABC

from cose.utils import _CoseAttribute


class CoseCurve(_CoseAttribute, ABC):
    """ Base class for all COSE curves. """

    _registered_curves = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_curves


##################################################
#            SUPPORTED COSE CURVES               #
##################################################


@CoseCurve.register_attribute()
class Reserved(CoseCurve):
    """
    Reserved

    Attributes:
        identifier     0

        fullname       RESERVED
    """

    identifier = 0
    fullname = "RESERVED"


@CoseCurve.register_attribute()
class P256(CoseCurve):
    """
    Curve NIST P-256

    Attributes:
        identifier     1

        fullname       P_256
    """

    identifier = 1
    fullname = "P_256"


@CoseCurve.register_attribute()
class P384(CoseCurve):
    """
    Curve NIST P-384

    Attributes:
        identifier     2

        fullname       P_384
    """

    identifier = 2
    fullname = "P_384"


@CoseCurve.register_attribute()
class P521(CoseCurve):
    """
    Curve NIST P-521

    Attributes:
        identifier     3

        fullname       P_521
    """

    identifier = 3
    fullname = "P_521"


@CoseCurve.register_attribute()
class X25519(CoseCurve):
    """
    Curve25519 for the Diffie-Hellman function (X25519)

    Attributes:
        identifier     4

        fullname       X25519
    """

    identifier = 4
    fullname = "X25519"


@CoseCurve.register_attribute()
class X448(CoseCurve):
    """
    Curve448 for the Diffie-Hellman function (X448)

    Attributes:
        identifier     5

        fullname       X448
    """

    identifier = 5
    fullname = "X448"


@CoseCurve.register_attribute()
class Ed25519(CoseCurve):
    """
    Curve25519 for the EdDSA algorithm (Ed25519)

    Attributes:
        identifier     6

        fullname       ED25519
    """

    identifier = 6
    fullname = "ED25519"


@CoseCurve.register_attribute()
class Ed448(CoseCurve):
    """
    Curve448 for the EdDSA algorithm (Ed448)

    Attributes:
        identifier     7

        fullname       ED448
    """

    identifier = 7
    fullname = "ED448"


@CoseCurve.register_attribute()
class SECP256K1(CoseCurve):
    """
    Curve secp256k1

    Attributes:
        identifier     8

        fullname       SECP256K1
    """

    identifier = 8
    fullname = "SECP256K1"


if __name__ == '__main__':
    print(CoseCurve.get_registered_classes())