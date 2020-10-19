from typing import Any, Callable, List

from aenum import Enum, MultiValue, skip

from cose import CoseAlgorithms
from cose.keys.cosekey import CoseKey
from cose.messages.signer import CounterSignature, CounterSignature0


class CoseHeaderKeys(Enum):
    """ COSE header parameters """

    _init_ = 'id fullname parser'
    _settings_ = MultiValue

    # Common Parameters
    RESERVED = 0, 'RESERVED', skip(None)
    ALG = 1, 'ALG', skip(CoseAlgorithms)
    CRIT = 2, 'CRIT', skip(None)
    CONTENT_TYPE = 3, 'CONTENT_TYPE', skip(None)
    KID = 4, 'KID', skip(None)
    IV = 5, 'IV', skip(None)
    PARTIAL_IV = 6, 'PARTIAL_IV', skip(None)
    COUNTER_SIGNATURE = 7, 'COUNTER_SIGNATURE', skip(CounterSignature.from_signature_obj)
    COUNTER_SIGNATURE0 = 9, 'COUNTER_SIGNATURE0', skip(CounterSignature0.from_signature_obj)
    KID_CONTEXT = 10, 'KID_CONTEXT', skip(None)

    # Elliptic Curve Key identifiers
    EPHEMERAL_KEY = -1, 'EPHEMERAL_KEY', skip(CoseKey.decode)
    STATIC_KEY = -2, 'STATIC_KEY', skip(CoseKey.decode)
    STATIC_KEY_ID = -3, 'STATIC_KEY_ID', skip(None)

    # HKDF Algorithm Parameters
    SALT = -20, 'SALT', skip(None)

    # Context Algorithm Parameters
    PARTY_U_IDENTITY = -21, 'PARTY_U_IDENTITY', skip(None)
    PARTY_U_NONCE = -22, 'PARTY_U_NONCE', skip(None)
    PARTY_U_OTHER = -23, 'PARTY_U_OTHER', skip(None)
    PARTY_V_IDENTITY = -24, 'PARTY_V_IDENTITY', skip(None)
    PARTY_V_NONCE = -25, 'PARTY_V_NONCE', skip(None)
    PARTY_V_OTHER = -26, 'PARTY_V_OTHER', skip(None)

    def __int__(self):
        return self.id

    def __str__(self):
        return self.fullname

    def __repr__(self):
        return f'<{self.__class__.__name__}.{self.fullname}: {self.id}>'

    def __eq__(self, other):
        return self.id == other or self.fullname == other

    def __hash__(self):
        return hash(self.id)


def parser(header_key: CoseHeaderKeys) -> Callable[[Any], Any]:
    return header_key.parser.value


def list_header_keys() -> List[CoseHeaderKeys]:
    return [k for k in CoseHeaderKeys.__members__.keys()]
