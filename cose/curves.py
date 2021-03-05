from abc import ABC

from cose.utils import _CoseAttribute


class CoseCurve(_CoseAttribute, ABC):
    _registered_curves = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_curves


@CoseCurve.register_attribute()
class Reserved(CoseCurve):
    identifier = 0
    fullname = "RESERVED"


@CoseCurve.register_attribute()
class P256(CoseCurve):
    identifier = 1
    fullname = "P_256"


@CoseCurve.register_attribute()
class P384(CoseCurve):
    identifier = 2
    fullname = "P_384"


@CoseCurve.register_attribute()
class P521(CoseCurve):
    identifier = 3
    fullname = "P_521"


@CoseCurve.register_attribute()
class X25519(CoseCurve):
    identifier = 4
    fullname = "X25519"


@CoseCurve.register_attribute()
class X448(CoseCurve):
    identifier = 5
    fullname = "X448"


@CoseCurve.register_attribute()
class Ed25519(CoseCurve):
    identifier = 6
    fullname = "ED25519"


@CoseCurve.register_attribute()
class Ed448(CoseCurve):
    identifier = 7
    fullname = "ED448"


@CoseCurve.register_attribute()
class SECP256K1(CoseCurve):
    identifier = 8
    fullname = "SECP256K1"


if __name__ == '__main__':
    print(CoseCurve.get_registered_classes())