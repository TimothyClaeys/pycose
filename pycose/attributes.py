from enum import IntEnum, unique


@unique
class CoseHeaderParam(IntEnum):
    """ COSE header parameters """
    # Common Parameters
    RESERVED = 0
    ALG = 1
    CRIT = 2
    CONTENT_TYPE = 3
    KID = 4
    IV = 5
    PARTIAL_IV = 6
    COUNTER_SIGNATURE = 7
    COUNTER_SIGNATURE0 = 9
    KID_CONTEXT = 10

    # Elliptic Curve Key identifiers
    EPHEMERAL_KEY = -1
    STATIC_KEY = - 2
    STATIC_KEY_ID = -3

    # HKDF Algorithm Parameters
    SALT = -20

    # Context Algorithm Parameters
    PARTY_U_IDENTITY = -21
    PARTY_U_NONCE = -22
    PARTY_U_OTHER = -23
    PARTY_V_IDENTITY = -24
    PARTY_V_NONCE = -25
    PARTY_V_OTHER = -26

    @classmethod
    def has_member(cls, item):
        return item in cls.__members__

    @classmethod
    def has_value(cls, value):
        return value in set(cls.__members__[attr] for attr in cls.__members__)


@unique
class CoseAlgorithm(IntEnum):
    ES512 = -37
    ES384 = -36
    ECDH_SS_A256KW = -34
    ECDH_SS_A192KW = -33
    ECDH_SS_A128KW = -32
    ECDH_ES_A256KW = -31
    ECDH_ES_A192KW = -30
    ECDH_ES_A128KW = -29
    ECDH_SS_HKDF_512 = -28
    ECDH_SS_HKDF_256 = -27
    ECDH_ES_HKDF_512 = -26
    ECDH_ES_HKDF_256 = -25
    DIRECT_HKDF_AES_256 = -13
    DIRECT_HKDF_SHA_128 = -12
    DIRECT_HKDF_SHA_512 = -11
    DIRECT_HKDF_SHA_256 = -10
    EDDSA = -8
    ES256 = -7
    DIRECT = -6
    A256KW = -5
    A192KW = -4
    A128KW = -3
    A128GCM = 1
    A192GCM = 2
    A256GCM = 3
    HMAC_256_64 = 4
    HMAC_256_256 = 5
    HMAC_384_384 = 6
    HMAC_512_512 = 7
    AES_CCM_16_64_128 = 10
    AES_CCM_16_64_256 = 11
    AES_CCM_64_64_128 = 12
    AES_CCM_64_64_256 = 13
    AES_MAC_128_64 = 14
    AES_MAC_256_64 = 15
    CHACHA20_POLY1305 = 24
    AES_MAC_128_128 = 25
    AES_MAC_256_128 = 26
    AES_CCM_16_128_128 = 30
    AES_CCM_16_128_256 = 31
    AES_CCM_64_128_128 = 32
    AES_CCM_64_128_256 = 33

    @classmethod
    def has_member(cls, item):
        return item in cls.__members__

    @classmethod
    def has_value(cls, value):
        return value in set(cls.__members__[attr] for attr in cls.__members__)
