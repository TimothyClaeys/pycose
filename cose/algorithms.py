from abc import ABC, abstractmethod
from binascii import hexlify, unhexlify
from hashlib import sha512, sha384, sha256
from typing import TYPE_CHECKING, Optional, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.ciphers import modes, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hashes import Hash, HashAlgorithm, SHA1, SHA256, SHA512, SHA384, SHAKE128, SHAKE256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from ecdsa.curves import Curve, NIST521p, NIST384p, NIST256p
from ecdsa.ellipticcurve import Point
from ecdsa.keys import SigningKey, VerifyingKey, BadSignatureError

from cose.exceptions import CoseException
from cose.headers import Algorithm
from cose.utils import _CoseAttribute

if TYPE_CHECKING:
    from cose.keys.symmetric import SK
    from cose.keys.ec2 import EC2
    from cose.keys.okp import OKP
    from cose.keys.rsa import RSA
    from cose.keys.curves import CoseCurve
    from cose.messages.context import CoseKDFContext


class CoseAlgorithm(_CoseAttribute, ABC):
    """ Base class for all COSE algorithms. """

    _registered_algorithms = {}

    @classmethod
    def get_registered_classes(cls):
        return cls._registered_algorithms


class _HashAlg(CoseAlgorithm, ABC):
    #: Set in derived class to hash constructor
    hash_cls = None
    #: Set in derived class to optional truncation size in byte count
    trunc_size: Optional[int] = None

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        return cls.hash_cls()

    @classmethod
    def compute_hash(cls, data: bytes) -> bytes:
        h = Hash(algorithm=cls.get_hash_func(), backend=default_backend())
        h.update(data)
        digest = h.finalize()

        if cls.trunc_size:
            digest = digest[:cls.trunc_size]

        return digest


class _EncAlg(CoseAlgorithm, ABC):
    @classmethod
    @abstractmethod
    def get_key_length(cls) -> int:
        raise NotImplementedError()


class _Rsa(CoseAlgorithm, ABC):
    """ RSA signing and (key-wrap) encryption. """

    @classmethod
    @abstractmethod
    def get_hash_func(cls):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_pad_func(cls, hash_cls):
        raise NotImplementedError()

    @classmethod
    def sign(cls, key: 'RSA', data: bytes) -> bytes:
        hash_cls = cls.get_hash_func()
        pad = cls.get_pad_func(hash_cls)

        public_nums = rsa.RSAPublicNumbers(e=int.from_bytes(key.e, 'big'), n=int.from_bytes(key.n, 'big'))
        private_nums = rsa.RSAPrivateNumbers(p=int.from_bytes(key.p, 'big'),
                                             q=int.from_bytes(key.q, 'big'),
                                             d=int.from_bytes(key.d, 'big'),
                                             dmp1=int.from_bytes(key.dp, 'big'),
                                             dmq1=int.from_bytes(key.dq, 'big'),
                                             iqmp=int.from_bytes(key.qinv, 'big'),
                                             public_numbers=public_nums)

        sk = private_nums.private_key(backend=default_backend())

        return sk.sign(data, pad, hash_cls())

    @classmethod
    def verify(cls, key: 'RSA', data: bytes, signature: bytes) -> bool:
        hash_cls = cls.get_hash_func()
        pad = cls.get_pad_func(hash_cls)

        public_nums = rsa.RSAPublicNumbers(e=int.from_bytes(key.e, 'big'), n=int.from_bytes(key.n, 'big'))
        pk = public_nums.public_key(backend=default_backend())

        try:
            pk.verify(signature, data, pad, hash_cls())
            return True
        except InvalidSignature:
            return False


class _RsaPss(_Rsa, ABC):
    """ RSA with PSS padding. """

    @classmethod
    def get_pad_func(cls, hash_cls):
        return padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=hash_cls.digest_size)


class _RsaOaep(_Rsa, ABC):
    """ RSA with OAEP padding. """

    @classmethod
    def get_pad_func(cls, hash_cls):
        return padding.OAEP(mgf=padding.MGF1(hash_cls()), algorithm=hash_cls(), label=None)

    @classmethod
    def key_wrap(cls, key: 'RSA', data: bytes) -> bytes:
        pad = cls.get_pad_func(cls.get_hash_func())

        public_nums = rsa.RSAPublicNumbers(e=int.from_bytes(key.e, 'big'), n=int.from_bytes(key.n, 'big'))
        pk = public_nums.public_key(backend=default_backend())

        return pk.encrypt(data, pad)

    @classmethod
    def key_unwrap(cls, key: 'RSA', data: bytes) -> bytes:
        pad = cls.get_pad_func(cls.get_hash_func())

        public_nums = rsa.RSAPublicNumbers(e=int.from_bytes(key.e, 'big'), n=int.from_bytes(key.n, 'big'))
        private_nums = rsa.RSAPrivateNumbers(p=int.from_bytes(key.p, 'big'),
                                             q=int.from_bytes(key.q, 'big'),
                                             d=int.from_bytes(key.d, 'big'),
                                             dmp1=int.from_bytes(key.dp, 'big'),
                                             dmq1=int.from_bytes(key.dq, 'big'),
                                             iqmp=int.from_bytes(key.qinv, 'big'),
                                             public_numbers=public_nums)

        sk = private_nums.private_key(backend=default_backend())

        return sk.decrypt(data, pad)


class _RsaPkcs1(_Rsa, ABC):
    """ RSA with PKCS#1 padding. """

    @classmethod
    def get_pad_func(cls, hash_cls):
        return padding.PKCS1v15()


class _Ecdsa(CoseAlgorithm, ABC):
    @classmethod
    @abstractmethod
    def get_curve(cls):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_hash_func(cls):
        raise NotImplementedError()

    @classmethod
    def sign(cls, key: 'EC2', data: bytes) -> bytes:
        sk = SigningKey.from_secret_exponent(int(hexlify(key.d), 16), curve=cls.get_curve())

        return sk.sign_deterministic(data, hashfunc=cls.get_hash_func())

    @classmethod
    def verify(cls, key: 'EC2', data: bytes, signature: bytes) -> bool:
        p = Point(curve=cls.get_curve().curve, x=int(hexlify(key.x), 16), y=int(hexlify(key.y), 16))

        vk = VerifyingKey.from_public_point(p, cls.get_curve(), cls.get_hash_func(), validate_point=True)

        try:
            return vk.verify(signature=signature, data=data, hashfunc=cls.get_hash_func())
        except BadSignatureError:
            return False


class _AesMac(CoseAlgorithm, ABC):
    @classmethod
    @abstractmethod
    def get_digest_length(cls) -> int:
        raise NotImplementedError()

    @classmethod
    def compute_tag(cls, key: 'SK', data: bytes):
        encryptor = Cipher(AES(key.k),
                           modes.CBC(unhexlify(b''.join([b'00'] * 16))),
                           backend=default_backend()).encryptor()

        while len(data) % 16 != 0:
            data += unhexlify(b"00")

        ciphertext = encryptor.update(data) + encryptor.finalize()
        if cls.get_digest_length() == 16:
            digest = ciphertext[-1 * cls.get_digest_length():]
        else:
            ciphertext = ciphertext[:-8]
            digest = ciphertext[-8:]

        return digest

    @classmethod
    def verify_tag(cls, key: 'SK', tag: bytes, data: bytes):
        computed_tag = cls.compute_tag(key, data)

        if tag == computed_tag:
            return True
        else:
            return False


class _HMAC(CoseAlgorithm, ABC):
    @classmethod
    @abstractmethod
    def get_digest_length(cls) -> int:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_hash_func(cls) -> HashAlgorithm:
        raise NotImplementedError()

    @classmethod
    def compute_tag(cls, key: 'SK', data: bytes):
        h = HMAC(key.k, cls.get_hash_func(), backend=default_backend())
        h.update(data)
        digest = h.finalize()

        return digest[:cls.get_digest_length()]

    @classmethod
    def verify_tag(cls, key: 'SK', tag: bytes, data: bytes) -> bool:

        computed_tag = cls.compute_tag(key, data)

        if tag == computed_tag:
            return True
        else:
            return False


class _AesKw(_EncAlg, ABC):

    @classmethod
    def key_wrap(cls, kek: 'SK', data: bytes):
        if cls.get_key_length() != len(kek.k):
            raise ValueError("Key has the wrong length")
        return aes_key_wrap(wrapping_key=kek.k, key_to_wrap=data, backend=default_backend())

    @classmethod
    def key_unwrap(cls, kek: 'SK', data: bytes):
        if cls.get_key_length() != len(kek.k):
            raise ValueError("Key has the wrong length")
        return aes_key_unwrap(wrapping_key=kek.k, wrapped_key=data, backend=default_backend())


class _EcdhHkdf(CoseAlgorithm, ABC):
    @classmethod
    @abstractmethod
    def get_hash_func(cls) -> HashAlgorithm:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_key_wrap_func(cls) -> _AesKw:
        raise NotImplementedError()

    @classmethod
    def _ecdh(cls, curve: 'CoseCurve', private_key: 'EC2', public_key: 'EC2') -> bytes:
        d_value = int(hexlify(private_key.d), 16)
        x_value = int(hexlify(public_key.x), 16)
        y_value = int(hexlify(public_key.y), 16)

        d = ec.derive_private_key(d_value, curve.curve_obj(), backend=default_backend())
        p = ec.EllipticCurvePublicNumbers(x_value, y_value, curve.curve_obj())
        p = p.public_key(backend=default_backend())

        shared_key = d.exchange(ECDH(), p)
        return shared_key

    @classmethod
    def derive_kek(cls, curve: 'CoseCurve', private_key: 'EC2', public_key: 'EC2', context: 'CoseKDFContext') -> bytes:
        shared_secret = cls._ecdh(curve, private_key, public_key)

        kdf = HKDF(algorithm=cls.get_hash_func(), length=context.supp_pub_info.key_data_length, salt=None,
                   info=context.encode(),
                   backend=default_backend())
        return kdf.derive(shared_secret)


class _AesGcm(_EncAlg, ABC):

    @classmethod
    def encrypt(cls, key: 'SK', nonce: bytes, data: bytes, external_aad: bytes) -> bytes:
        cipher = AESGCM(key=key.k)
        return cipher.encrypt(nonce=nonce, data=data, associated_data=external_aad)

    @classmethod
    def decrypt(cls, key: 'SK', nonce: bytes, ciphertext: bytes, external_aad: bytes) -> bytes:
        cipher = AESGCM(key=key.k)
        return cipher.decrypt(nonce=nonce, data=ciphertext, associated_data=external_aad)


class _AesCcm(_EncAlg, ABC):

    @classmethod
    @abstractmethod
    def get_tag_length(cls) -> int:
        raise NotImplementedError()

    @classmethod
    def encrypt(cls, key: 'SK', nonce: bytes, data: bytes, external_aad: bytes) -> bytes:
        cipher = AESCCM(key.k, tag_length=cls.get_tag_length())
        return cipher.encrypt(nonce, data=data, associated_data=external_aad)

    @classmethod
    def decrypt(cls, key: 'SK', nonce: bytes, ciphertext: bytes, external_aad: bytes) -> bytes:
        cipher = AESCCM(key=key.k, tag_length=cls.get_tag_length())
        return cipher.decrypt(nonce, data=ciphertext, associated_data=external_aad)


##################################################
#            SUPPORTED COSE ALGORITHMS           #
##################################################

@CoseAlgorithm.register_attribute()
class RsaPkcs1Sha1(_RsaPkcs1):
    """
    RSASSA-PKCS1-v1_5 using SHA-1

    Attributes:
        identifier     -65565

        fullname       RS1
    """

    identifier = -65535
    fullname = "RS1"

    @classmethod
    def get_hash_func(cls):
        return SHA1


@CoseAlgorithm.register_attribute()
class RsaPkcs1Sha512(_RsaPkcs1):
    """
    RSASSA-PKCS1-v1_5 using SHA-512

    Attributes:
        identifier     -259

        fullname       RS512
    """

    identifier = -259
    fullname = "RS512"

    @classmethod
    def get_hash_func(cls):
        return SHA512


@CoseAlgorithm.register_attribute()
class RsaPkcs1Sha384(_RsaPkcs1):
    """
    RSASSA-PKCS1-v1_5 using SHA-512

    Attributes:
        identifier     -258

        fullname       RS384
    """
    identifier = -258
    fullname = "RS384"

    @classmethod
    def get_hash_func(cls):
        return SHA384


@CoseAlgorithm.register_attribute()
class RsaPkcs1Sha256(_RsaPkcs1):
    """
    RSASSA-PKCS1-v1_5 using SHA-512

    Attributes:
        identifier     -257

        fullname       RS256
    """

    identifier = -257
    fullname = "RS256"

    @classmethod
    def get_hash_func(cls):
        return SHA256


@CoseAlgorithm.register_attribute()
class Shake256(_HashAlg):
    """
    SHAKE-256 512-bit Hash Value

    Attributes:
        identifier     -45

        fullname       SHAKE-256
    """

    identifier = -45
    fullname = "SHAKE-256"
    hash_cls = SHAKE256


@CoseAlgorithm.register_attribute()
class Sha512(_HashAlg):
    """
    SHA-2 512-bit Hash

    Attributes:
        identifier     -46

        fullname       SHA-512
    """

    identifier = -44
    fullname = "SHA-512"
    hash_cls = SHA512


@CoseAlgorithm.register_attribute()
class Sha384(_HashAlg):
    """
    SHA-2 384-bit Hash

    Attributes:
        identifier     -43

        fullname       SHA-384

    """

    identifier = -43
    fullname = "SHA-384"
    hash_cls = SHA384


@CoseAlgorithm.register_attribute()
class RsaesOaepSha512(_RsaOaep):
    identifier = -42
    fullname = "RSAES_OAEP_SHA_512"

    @classmethod
    def get_hash_func(cls):
        return SHA512


@CoseAlgorithm.register_attribute()
class RsaesOaepSha256(_RsaOaep):
    identifier = -41
    fullname = "RSAES_OAEP_SHA_256"

    @classmethod
    def get_hash_func(cls):
        return SHA256


@CoseAlgorithm.register_attribute()
class RsaesOaepSha1(_RsaOaep):
    identifier = -40
    fullname = "RSAES_OAEP_SHA_1"

    @classmethod
    def get_hash_func(cls):
        return SHA1


@CoseAlgorithm.register_attribute()
class Ps512(_RsaPss):
    identifier = -39
    fullname = "PS512"

    @classmethod
    def get_hash_func(cls):
        return SHA512


@CoseAlgorithm.register_attribute()
class Ps384(_RsaPss):
    identifier = -38
    fullname = "PS384"

    @classmethod
    def get_hash_func(cls):
        return SHA384


@CoseAlgorithm.register_attribute()
class Ps256(_RsaPss):
    identifier = -37
    fullname = "PS256"

    @classmethod
    def get_hash_func(cls):
        return SHA256


@CoseAlgorithm.register_attribute()
class Es512(_Ecdsa):
    """
    ECDSA w/ SHA-512

    Attributes:
        identifier     -36

        fullname       ES512

    """

    identifier = -36
    fullname = "ES512"

    @classmethod
    def get_hash_func(cls):
        """ Returns a hash function used with this algorithm """
        return sha512

    @classmethod
    def get_curve(cls) -> Curve:
        """ Returns a curve object used with this algorithm """
        return NIST521p


@CoseAlgorithm.register_attribute()
class Es384(_Ecdsa):
    """
    ECDSA w/ SHA-384

    Attributes:
        identifier     -35

        fullname       ES384
    """

    identifier = -35
    fullname = "ES384"

    @classmethod
    def get_hash_func(cls):
        """ Returns a hash function used with this algorithm """
        return sha384

    @classmethod
    def get_curve(cls) -> Curve:
        """ Returns a curve object used with this algorithm """
        return NIST384p


@CoseAlgorithm.register_attribute()
class EcdhSsA256KW(_EcdhHkdf):
    """
    ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key

    Attributes:
        identifier     -34

        fullname       ECDH_SS_A256KW
    """

    identifier = -34
    fullname = "ECDH_SS_A256KW"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return A256KW

    @classmethod
    def get_key_length(cls) -> int:
        """ Returns the key length of the wrapping function """
        return cls.get_key_wrap_func().get_key_length()


@CoseAlgorithm.register_attribute()
class EcdhSsA192KW(_EcdhHkdf):
    """
    ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key

    Attributes:
        identifier     -33

        fullname       ECDH_SS_A192KW
    """

    identifier = -33
    fullname = "ECDH_SS_A192KW"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return A192KW

    @classmethod
    def get_key_length(cls) -> int:
        """ Returns the key length of the wrapping function """
        return cls.get_key_wrap_func().get_key_length()


@CoseAlgorithm.register_attribute()
class EcdhSsA128KW(_EcdhHkdf):
    """
    ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key

    Attributes:
        identifier     -32

        fullname       ECDH_SS_A128KW
    """

    identifier = -32
    fullname = "ECDH_SS_A128KW"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return A128KW

    @classmethod
    def get_key_length(cls) -> int:
        """ Returns the key length of the wrapping function """
        return cls.get_key_wrap_func().get_key_length()


@CoseAlgorithm.register_attribute()
class EcdhEsA256KW(_EcdhHkdf):
    """
    ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key

    Attributes:
        identifier     -33

        fullname       ECDH_ES_A256KW
    """

    identifier = -31
    fullname = "ECDH_ES_A256KW"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return A256KW

    @classmethod
    def get_key_length(cls) -> int:
        """ Returns the key length of the wrapping function """
        return cls.get_key_wrap_func().get_key_length()


@CoseAlgorithm.register_attribute()
class EcdhEsA192KW(_EcdhHkdf):
    """
    ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key

    Attributes:
        identifier     -30

        fullname       ECDH_ES_A192KW
    """

    identifier = -30
    fullname = "ECDH_ES_A192KW"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return A192KW

    @classmethod
    def get_key_length(cls) -> int:
        """ Returns the key length of the wrapping function """
        return cls.get_key_wrap_func().get_key_length()


@CoseAlgorithm.register_attribute()
class EcdhEsA128KW(_EcdhHkdf):
    """
    ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key

    Attributes:
        identifier     -29

        fullname       ECDH_ES_A128KW
    """

    identifier = -29
    fullname = "ECDH_ES_A128KW"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return A128KW()

    @classmethod
    def get_key_length(cls) -> int:
        """ Returns the key length of the wrapping function """
        return cls.get_key_wrap_func().get_key_length()


@CoseAlgorithm.register_attribute()
class EcdhSsHKDF512(_EcdhHkdf):
    """
    ECDH SS w/ HKDF - generate key directly

    Attributes:
        identifier     -28

        fullname       ECDH_SS_HKDF_512
    """

    identifier = -28
    fullname = "ECDH_SS_HKDF_512"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA512()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return Direct()


@CoseAlgorithm.register_attribute()
class EcdhSsHKDF256(_EcdhHkdf):
    """
    ECDH SS w/ HKDF - generate key directly

    Attributes:
        identifier     -27

        fullname       ECDH_SS_HKDF_256
    """

    identifier = -27
    fullname = "ECDH_SS_HKDF_256"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return Direct()


@CoseAlgorithm.register_attribute()
class EcdhEsHKDF512(_EcdhHkdf):
    """
    ECDH ES w/ HKDF - generate key directly

    Attributes:
        identifier     -26

        fullname       ECDH_ES_HKDF_512
    """

    identifier = -26
    fullname = "ECDH_ES_HKDF_512"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA512()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return Direct()


@CoseAlgorithm.register_attribute()
class EcdhEsHKDF256(_EcdhHkdf):
    """
    ECDH ES w/ HKDF - generate key directly

    Attributes:
        identifier     -25

        fullname       ECDH_ES_HKDF_256
    """

    identifier = -25
    fullname = "ECDH_ES_HKDF_256"

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        """ Returns a hash function used with this algorithm """
        return SHA256()

    @classmethod
    def get_key_wrap_func(cls):
        """ Returns a key wrap function used with this algorithm """
        return Direct()


@CoseAlgorithm.register_attribute()
class Shake128(_HashAlg):
    """
    SHAKE-128 256-bit Hash Value

    Attributes:
        identifier     -18

        fullname       SHAKE-128
    """

    identifier = -18
    fullname = "SHAKE-128"
    hash_cls = SHAKE128


@CoseAlgorithm.register_attribute()
class Sha512Trunc256(_HashAlg):
    """
    SHA-2 512-bit Hash truncated to 256-bits

    Attributes:
        identifier     -17

        fullname       "SHA-512/256"-256
    """

    identifier = -17
    fullname = "SHA-512/256"
    hash_cls = SHA512
    trunc_size = 32


@CoseAlgorithm.register_attribute()
class Sha256(_HashAlg):
    """
    SHA-2 256-bit Hash

    Attributes:
        identifier     -16

        fullname       SHA-256
    """

    identifier = -16
    fullname = "SHA-256"
    hash_cls = SHA256


@CoseAlgorithm.register_attribute()
class Sha256Trunc64(_HashAlg):
    """
    SHA-2 256-bit Hash truncated to 64-bits

    Attributes:
        identifier     -15

        fullname       SHA256/64
    """

    identifier = -15
    fullname = "SHA-256/64"
    hash_cls = SHA256
    trunc_size = 8


@CoseAlgorithm.register_attribute()
class Sha1(_HashAlg):
    """
    SHA-1 Hash

    Attributes:
        identifier     -14

        fullname       SHA-1
    """

    identifier = -14
    fullname = "SHA-1"
    hash_cls = SHA1


@CoseAlgorithm.register_attribute()
class DirectHKDFAES256(CoseAlgorithm):
    """
    Shared secret w/ AES-MAC 256-bit key

    Attributes:
        identifier     -13

        fullname       DIRECT_HKDF_AES_256
    """

    identifier = - 13
    fullname = "DIRECT_HKDF_AES_256"


@CoseAlgorithm.register_attribute()
class DirectHKDFAES128(CoseAlgorithm):
    """
    Shared secret w/ AES-MAC 128-bit key

    Attributes:
        identifier     -12

        fullname       DIRECT_HKDF_AES_128
    """
    identifier = - 12
    fullname = "DIRECT_HKDF_AES_128"


@CoseAlgorithm.register_attribute()
class DirecHKDFSHA512(CoseAlgorithm):
    """
    Shared secret w/ HKDF and SHA-512

    Attributes:
        identifier     -11

        fullname       DIRECT_HKDF_SHA_512
    """

    identifier = - 11
    fullname = "DIRECT_HKDF_SHA_512"


@CoseAlgorithm.register_attribute()
class DirectHKDFSHA256(CoseAlgorithm):
    """
    Shared secret w/ HKDF and SHA-256

    Attributes:
        identifier     -10

        fullname       DIRECT_HKDF_SHA_256
    """

    identifier = - 10
    fullname = "DIRECT_HKDF_SHA_256"


@CoseAlgorithm.register_attribute()
class EdDSA(CoseAlgorithm):
    """
    EdDSA

    Attributes:
        identifier     -8

        fullname       EDDSA
    """

    identifier = -8
    fullname = "EDDSA"

    @classmethod
    def sign(cls, key: 'OKP', data: bytes) -> bytes:
        if key.crv.fullname == 'ED25519':
            sk = Ed25519PrivateKey.from_private_bytes(key.d)
        elif key.crv.fullname == 'ED448':
            sk = Ed448PrivateKey.from_private_bytes(key.d)
        else:
            raise CoseException(f"Illegal curve for OKP singing: {key.crv}")

        return sk.sign(data)

    @classmethod
    def verify(cls, key: 'OKP', data: bytes, signature: bytes) -> bool:
        if key.crv.fullname == 'ED25519':
            vk = Ed25519PublicKey.from_public_bytes(key.x)
        elif key.crv.fullname == 'ED448':
            vk = Ed448PublicKey.from_public_bytes(key.x)
        else:
            raise CoseException(f"Illegal curve for OKP singing: {key.crv}")

        try:
            vk.verify(signature, data)
            return True
        except InvalidSignature:
            return False


@CoseAlgorithm.register_attribute()
class Es256(_Ecdsa):
    """
    ECDSA w/ SHA-256

    Attributes:
        identifier     -7

        fullname       ES256
    """

    identifier = -7
    fullname = "ES256"

    @classmethod
    def get_hash_func(cls):
        return sha256

    @classmethod
    def get_curve(cls) -> Curve:
        return NIST256p


@CoseAlgorithm.register_attribute()
class Direct(CoseAlgorithm):
    """
    Direct use of CEK

    Attributes:
        identifier     -6

        fullname       DIRECT
    """

    identifier = -6
    fullname = "DIRECT"


@CoseAlgorithm.register_attribute()
class A256KW(_AesKw):
    """
    AES Key Wrap w/ 256-bit key

    Attributes:
        identifier     -5

        fullname       A256KW
    """

    identifier = -5
    fullname = "A256KW"

    @classmethod
    def get_key_length(cls) -> int:
        return 32


@CoseAlgorithm.register_attribute()
class A192KW(_AesKw):
    """
    AES Key Wrap w/ 192-bit key

    Attributes:
        identifier     -4

        fullname       A192KW
    """

    identifier = -4
    fullname = "A192KW"

    @classmethod
    def get_key_length(cls) -> int:
        return 24


@CoseAlgorithm.register_attribute()
class A128KW(_AesKw):
    """
    AES Key Wrap w/ 128-bit key

    Attributes:
        identifier     -3

        fullname       A128KW
    """

    identifier = -3
    fullname = "A128KW"

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class A128GCM(_AesGcm):
    """
    AES-GCM mode w/ 128-bit key, 128-bit tag

    Attributes:
        identifier     1

        fullname       A128GCM
    """

    identifier = 1
    fullname = 'A128GCM'

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class A192GCM(_AesGcm):
    """
    AES-GCM mode w/ 192-bit key, 128-bit tag

    Attributes:
        identifier     2

        fullname       A192GCM
    """

    identifier = 2
    fullname = 'A192GCM'

    @classmethod
    def get_key_length(cls) -> int:
        return 24


@CoseAlgorithm.register_attribute()
class A256GCM(_AesGcm):
    """
    AES-GCM mode w/ 256-bit key, 128-bit tag

    Attributes:
        identifier     3

        fullname       A256CM
    """

    identifier = 3
    fullname = 'A256GCM'

    @classmethod
    def get_key_length(cls) -> int:
        return 32


@CoseAlgorithm.register_attribute()
class HMAC25664(_HMAC):
    identifier = 4
    fullname = 'HMAC_256_64'

    @classmethod
    def get_digest_length(cls) -> int:
        return 8

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        return SHA256()


@CoseAlgorithm.register_attribute()
class HMAC256(_HMAC):
    identifier = 5
    fullname = 'HMAC_256'

    @classmethod
    def get_digest_length(cls) -> int:
        return 32

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        return SHA256()


@CoseAlgorithm.register_attribute()
class HMAC384(_HMAC):
    identifier = 6
    fullname = 'HMAC_384'

    @classmethod
    def get_digest_length(cls) -> int:
        return 48

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        return SHA384()


@CoseAlgorithm.register_attribute()
class HMAC512(_HMAC):
    identifier = 7
    fullname = 'HMAC_512'

    @classmethod
    def get_digest_length(cls) -> int:
        return 64

    @classmethod
    def get_hash_func(cls) -> HashAlgorithm:
        return SHA512()


@CoseAlgorithm.register_attribute()
class AESCCM1664128(_AesCcm):
    identifier = 10
    fullname = 'AES_CCM_16_64_128'

    @classmethod
    def get_tag_length(cls) -> int:
        return 8

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class AESCCM1664256(_AesCcm):
    identifier = 11
    fullname = 'AES_CCM_16_64_256'

    @classmethod
    def get_tag_length(cls) -> int:
        return 8

    @classmethod
    def get_key_length(cls) -> int:
        return 32


@CoseAlgorithm.register_attribute()
class AESCCM6464128(_AesCcm):
    identifier = 12
    fullname = 'AES_CCM_64_64_128'

    @classmethod
    def get_tag_length(cls) -> int:
        return 8

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class AESCCM6464256(_AesCcm):
    identifier = 13
    fullname = 'AES_CCM_64_64_256'

    @classmethod
    def get_key_length(cls) -> int:
        return 32

    @classmethod
    def get_tag_length(cls) -> int:
        return 8


@CoseAlgorithm.register_attribute()
class AESMAC12864(_AesMac):
    identifier = 14
    fullname = 'AES_MAC_128_64'

    @classmethod
    def get_digest_length(cls) -> int:
        return 8

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class AESMAC25664(_AesMac):
    identifier = 15
    fullname = 'AES_MAC_256_64'

    @classmethod
    def get_digest_length(cls) -> int:
        return 8

    @classmethod
    def get_key_length(cls) -> int:
        return 32


@CoseAlgorithm.register_attribute()
class AESMAC128128(_AesMac):
    identifier = 25
    fullname = 'AES_MAC_128_128'

    @classmethod
    def get_digest_length(cls) -> int:
        return 16

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class AESMAC256128(_AesMac):
    identifier = 26
    fullname = 'AES_MAC_256_128'

    @classmethod
    def get_digest_length(cls) -> int:
        return 16

    @classmethod
    def get_key_length(cls) -> int:
        return 32


@CoseAlgorithm.register_attribute()
class AESCCM16128128(_AesCcm):
    identifier = 30
    tag_length = 16
    fullname = 'AES_CCM_16_128_128'

    @classmethod
    def get_tag_length(cls) -> int:
        return 16

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class AESCCM16128256(_AesCcm):
    identifier = 31
    fullname = 'AES_CCM_16_128_256'

    @classmethod
    def get_tag_length(cls) -> int:
        return 16

    @classmethod
    def get_key_length(cls) -> int:
        return 32


@CoseAlgorithm.register_attribute()
class AESCCM64128128(_AesCcm):
    identifier = 32
    fullname = 'AES_CCM_64_128_128'

    @classmethod
    def get_tag_length(cls) -> int:
        return 16

    @classmethod
    def get_key_length(cls) -> int:
        return 16


@CoseAlgorithm.register_attribute()
class AESCCM64128256(_AesCcm):
    identifier = 33
    fullname = 'AES_CCM_64_128_256'

    @classmethod
    def get_tag_length(cls) -> int:
        return 16

    @classmethod
    def get_key_length(cls) -> int:
        return 32


# set parser
Algorithm.value_parser = CoseAlgorithm.from_id

CoseAlg = TypeVar('CoseAlg', bound=CoseAlgorithm)

if __name__ == '__main__':
    print(CoseAlgorithm.get_registered_classes())
