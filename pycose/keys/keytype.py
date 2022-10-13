from abc import ABC
from typing import TypeVar

from pycose.utils import _CoseAttribute


class KTY(_CoseAttribute, ABC):
    _registered_algorithms = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


@KTY.register_attribute()
class KtyReserved(KTY):
    identifier = 0
    fullname = 'RESERVED'


@KTY.register_attribute()
class KtyOKP(KTY):
    identifier = 1
    fullname = 'OKP'


@KTY.register_attribute()
class KtyEC2(KTY):
    identifier = 2
    fullname = 'EC2'


@KTY.register_attribute()
class KtyRSA(KTY):
    identifier = 3
    fullname = 'RSA'


@KTY.register_attribute()
class KtySymmetric(KTY):
    identifier = 4
    fullname = 'SYMMETRIC'


KTYPE = TypeVar('KTYPE', bound=KTY)

if __name__ == '__main__':
    print(KTY.get_registered_classes())
