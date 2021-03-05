from abc import ABC

from cose.algorithms import CoseAlgorithm
from cose.keys.keyops import KeyOps
from cose.keys.keytype import KTY
from cose.utils import _CoseAttribute


class KeyParam(_CoseAttribute, ABC):
    _registered_algorithms = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


@KeyParam.register_attribute()
class KpKty(KeyParam):
    identifier = 1
    fullname = 'KTY'


@KeyParam.register_attribute()
class KpKid(KeyParam):
    identifier = 2
    fullname = 'KID'


@KeyParam.register_attribute()
class KpAlg(KeyParam):
    identifier = 3
    fullname = 'ALG'


@KeyParam.register_attribute()
class KpKeyOps(KeyParam):
    identifier = 4
    fullname = 'KEY_OPS'


@KeyParam.register_attribute()
class KpBaseIV(KeyParam):
    identifier = 5
    fullname = 'BASE_IV'


class EC2KeyParam(_CoseAttribute, ABC):
    _registered_algorithms = {}
    _registered_algorithms.update(KeyParam.get_registered_classes())

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


@EC2KeyParam.register_attribute()
class EC2KpCurve(EC2KeyParam):
    identifier = -1
    fullname = "CURVE"


@EC2KeyParam.register_attribute()
class EC2KpX(EC2KeyParam):
    identifier = -2
    fullname = "X"


@EC2KeyParam.register_attribute()
class EC2KpY(EC2KeyParam):
    identifier = -3
    fullname = "Y"


@EC2KeyParam.register_attribute()
class EC2KpD(EC2KeyParam):
    identifier = -4
    fullname = "D"


class OKPKeyParam(_CoseAttribute, ABC):
    _registered_algorithms = {}
    _registered_algorithms.update(KeyParam.get_registered_classes())

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


@OKPKeyParam.register_attribute()
class OKPKpCurve(OKPKeyParam):
    identifier = -1
    fullname = "CURVE"


@OKPKeyParam.register_attribute()
class OKPKpD(OKPKeyParam):
    identifier = -4
    fullname = "D"


@OKPKeyParam.register_attribute()
class OKPKpX(OKPKeyParam):
    identifier = -2
    fullname = "X"


class RSAKeyParam(_CoseAttribute, ABC):
    _registered_algorithms = {}
    _registered_algorithms.update(KeyParam.get_registered_classes())

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


@RSAKeyParam.register_attribute()
class RSAKpN(RSAKeyParam):
    identifier = -1
    fullname = "N"


@RSAKeyParam.register_attribute()
class RSAKpE(RSAKeyParam):
    identifier = -2
    fullname = "E"


@RSAKeyParam.register_attribute()
class RSAKpD(RSAKeyParam):
    identifier = -3
    fullname = "D"


@RSAKeyParam.register_attribute()
class RSAKpP(RSAKeyParam):
    identifier = -4
    fullname = "P"


@RSAKeyParam.register_attribute()
class RSAKpQ(RSAKeyParam):
    identifier = -5
    fullname = "Q"


@RSAKeyParam.register_attribute()
class RSAKpDP(RSAKeyParam):
    identifier = -6
    fullname = "DP"


@RSAKeyParam.register_attribute()
class RSAKpDQ(RSAKeyParam):
    identifier = -7
    fullname = "DQ"


@RSAKeyParam.register_attribute()
class RSAKpQInv(RSAKeyParam):
    identifier = -8
    fullname = "QINV"


@RSAKeyParam.register_attribute()
class RSAKpOther(RSAKeyParam):
    identifier = -9
    fullname = "OTHER"


class SymmetricKeyParam(_CoseAttribute, ABC):
    _registered_algorithms = {}
    _registered_algorithms.update(KeyParam.get_registered_classes())

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


@SymmetricKeyParam.register_attribute()
class SymKpK(SymmetricKeyParam):
    identifier = -1
    fullname = "K"


KpKty.value_parser = KTY.from_id
KpKeyOps.value_parser = KeyOps.from_id
KpAlg.value_parser = CoseAlgorithm.from_id

if __name__ == '__main__':
    print(KeyParam.get_registered_classes())
