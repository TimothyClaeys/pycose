from abc import ABC
from typing import TypeVar

from pycose.utils import _CoseAttribute


class KeyOps(_CoseAttribute, ABC):
    _registered_algorithms = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


@KeyOps.register_attribute()
class SignOp(KeyOps):
    identifier = 1
    fullname = 'SIGN'


@KeyOps.register_attribute()
class VerifyOp(KeyOps):
    identifier = 2
    fullname = 'VERIFY'


@KeyOps.register_attribute()
class EncryptOp(KeyOps):
    identifier = 3
    fullname = 'ENCRYPT'


@KeyOps.register_attribute()
class DecryptOp(KeyOps):
    identifier = 4
    fullname = 'DECRYPT'


@KeyOps.register_attribute()
class WrapOp(KeyOps):
    identifier = 5
    fullname = 'WRAP'


@KeyOps.register_attribute()
class UnwrapOp(KeyOps):
    identifier = 6
    fullname = 'UNWRAP'


@KeyOps.register_attribute()
class DeriveKeyOp(KeyOps):
    identifier = 7
    fullname = 'DERIVE_KEY'


@KeyOps.register_attribute()
class DeriveBitsOp(KeyOps):
    identifier = 8
    fullname = 'DERIVE_BITS'


@KeyOps.register_attribute()
class MacCreateOp(KeyOps):
    identifier = 9
    fullname = 'MAC_CREATE'


@KeyOps.register_attribute()
class MacVerifyOp(KeyOps):
    identifier = 10
    fullname = 'MAC_VERIFY'


KEYOPS = TypeVar('KEYOPS', bound=KeyOps)

if __name__ == '__main__':
    print(KeyOps.get_registered_classes())
