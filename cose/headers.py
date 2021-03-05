from abc import ABC

from cose.utils import _CoseAttribute


class CoseHeaderAttribute(_CoseAttribute, ABC):
    _registered_attributes = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_attributes


@CoseHeaderAttribute.register_attribute()
class Reserved(CoseHeaderAttribute):
    identifier = 0
    fullname = "RESERVED"


@CoseHeaderAttribute.register_attribute()
class Algorithm(CoseHeaderAttribute):
    identifier = 1
    fullname = "ALG"


@CoseHeaderAttribute.register_attribute()
class Critical(CoseHeaderAttribute):
    identifier = 2
    fullname = "CRITICAL"


@CoseHeaderAttribute.register_attribute()
class ContentType(CoseHeaderAttribute):
    identifier = 3
    fullname = "CONTENT_TYPE"


@CoseHeaderAttribute.register_attribute()
class KID(CoseHeaderAttribute):
    identifier = 4
    fullname = "KID"


@CoseHeaderAttribute.register_attribute()
class IV(CoseHeaderAttribute):
    identifier = 5
    fullname = "IV"


@CoseHeaderAttribute.register_attribute()
class PartialIV(CoseHeaderAttribute):
    identifier = 6
    fullname = "PARTIAL_IV"


@CoseHeaderAttribute.register_attribute()
class CounterSignature(CoseHeaderAttribute):
    identifier = 7
    fullname = "COUNTER_SIGN"


@CoseHeaderAttribute.register_attribute()
class CounterSignature0(CoseHeaderAttribute):
    identifier = 9
    fullname = "COUNTER_SIGN0"


@CoseHeaderAttribute.register_attribute()
class KIDContext(CoseHeaderAttribute):
    identifier = 10
    fullname = "KID_CONTEXT"


@CoseHeaderAttribute.register_attribute()
class X5bag(CoseHeaderAttribute):
    identifier = 32
    fullname = "X5_BAG"


@CoseHeaderAttribute.register_attribute()
class X5chain(CoseHeaderAttribute):
    identifier = 33
    fullname = "X5_CHAIN"


@CoseHeaderAttribute.register_attribute()
class X5t(CoseHeaderAttribute):
    identifier = 34
    fullname = "X5_T"


@CoseHeaderAttribute.register_attribute()
class X5u(CoseHeaderAttribute):
    identifier = 35
    fullname = "X5_U"


@CoseHeaderAttribute.register_attribute()
class EphemeralKey(CoseHeaderAttribute):
    identifier = -1
    fullname = "EPHEMERAL_KEY"


@CoseHeaderAttribute.register_attribute()
class StaticKey(CoseHeaderAttribute):
    identifier = -2
    fullname = "STATIC_KEY"


@CoseHeaderAttribute.register_attribute()
class StaticKeyID(CoseHeaderAttribute):
    identifier = -3
    fullname = "STATIC_KEY_ID"


@CoseHeaderAttribute.register_attribute()
class Salt(CoseHeaderAttribute):
    identifier = -20
    fullname = "SALT"


@CoseHeaderAttribute.register_attribute()
class PartyUID(CoseHeaderAttribute):
    identifier = -21
    fullname = "PARTY_U_ID"


@CoseHeaderAttribute.register_attribute()
class PartyUNonce(CoseHeaderAttribute):
    identifier = -22
    fullname = "PARTY_U_NONCE"


@CoseHeaderAttribute.register_attribute()
class PartyUOther(CoseHeaderAttribute):
    identifier = -23
    fullname = "PARTY_U_OTHER"


@CoseHeaderAttribute.register_attribute()
class PartyVID(CoseHeaderAttribute):
    identifier = -24
    fullname = "PARTY_V_ID"


@CoseHeaderAttribute.register_attribute()
class PartyVNonce(CoseHeaderAttribute):
    identifier = -25
    fullname = "PARTY_V_NONCE"


@CoseHeaderAttribute.register_attribute()
class PartyVOther(CoseHeaderAttribute):
    identifier = -26
    fullname = "PARTY_V_OTHER"


# do not register (not official IANA values)
class SuppPubOther(CoseHeaderAttribute):
    identifier = -998
    fullname = "SUPP_PUB_OTHER"


# do not register (not official IANA values)
class SuppPrivOther(CoseHeaderAttribute):
    identifier = -999
    fullname = "SUPP_PRIV_OTHER"


if __name__ == '__main__':
    print(CoseHeaderAttribute.get_registered_classes())
