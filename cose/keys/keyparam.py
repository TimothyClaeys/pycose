import pprint
from abc import ABC
from typing import TypeVar, Union, Type

from cose.algorithms import CoseAlgorithm
from cose.keys.keyops import KeyOps
from cose.keys.keytype import KTY
from cose.utils import _CoseAttribute


#########################################
# Base Key Parameters
#########################################

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


#########################################
# EC2 Key Parameters
#########################################

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


#########################################
# OKP Key Parameters
#########################################

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


#########################################
# Symmetric Key Parameters
#########################################

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

KPBASE = TypeVar('KPBASE', bound=KeyParam)
EC2KP = TypeVar('EC2KP', bound=EC2KeyParam)
OKPKP = TypeVar('OKPKP', bound=OKPKeyParam)
SYMKP = TypeVar('SYMKP', bound=SymmetricKeyParam)
KP = Union[Type['KP'], Type['OKPKP'], Type['EC2KP'], Type['SYMKP']]
if __name__ == '__main__':
    print("\nBASE KEY PARAMETERS:")
    pprint.pprint(KeyParam.get_registered_classes())

    print("\nRSA KEY PARAMETERS:")
    pprint.pprint(RSAKeyParam.get_registered_classes())

    print("\nEC2 KEY PARAMETERS:")
    pprint.pprint(EC2KeyParam.get_registered_classes())

    print("\nOKP KEY PARAMETERS:")
    pprint.pprint(OKPKeyParam.get_registered_classes())

    print("\nSYMMETRIC KEY PARAMETERS:")
    pprint.pprint(SymmetricKeyParam.get_registered_classes())
