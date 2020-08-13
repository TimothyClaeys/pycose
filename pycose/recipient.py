import sys
from binascii import hexlify
from typing import Union, List, Optional, Any, Tuple

from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey

from pycose import CoseMessage
from pycose.cosebase import HeaderKeys

if sys.version_info.minor < 8:
    from singledispatchmethod import singledispatchmethod
else:
    from functools import singledispatchmethod

from pycose.attributes import CoseAlgorithm
from pycose.cosekey import SymmetricKey, EC2, OKP
from pycose.crypto import key_wrap, CoseKDFContext, KEY_DERIVATION_CURVES, ecdh_key_derivation, key_unwrap, \
    x25519_key_derivation, hmac_hkdf_key_derivation


class CoseRecipient(CoseMessage):
    @classmethod
    def recursive_encode(
            cls,
            recipients: List['CoseRecipient'],
            crypto_params:
            Tuple[Tuple[bool, Union[CoseAlgorithm, None], Union[SymmetricKey, None], Union[Tuple[Any], None]]] = None
    ) -> list:
        """ Recursively encode/encrypt the recipients """
        if crypto_params is None:
            recipients = [r.encode() for r in recipients]
        else:
            if len(crypto_params) != len(recipients):
                raise ValueError("'crypto_params' should have the same length as the internal recipients list.")
            recipients = [r.encode(*p) for r, p in zip(recipients, crypto_params)]

        return recipients

    @classmethod
    def from_recipient_obj(cls, recipient_obj: list):
        msg = super().from_cose_obj(recipient_obj)

        try:
            recipient_list = recipient_obj.pop(0)
            msg.recipient_list = [CoseRecipient.from_recipient_obj(r) for r in recipient_list]
        except IndexError:
            msg.recipient_list = None

        return msg

    def __init__(self, phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 key: Optional[SymmetricKey] = None,
                 recipients: Optional[List] = None):
        super().__init__(phdr=phdr, uhdr=uhdr, payload=payload, key=key)

        self.recipients = [] if recipients is None else recipients

    @property
    def key_bytes(self) -> bytes:
        if self.key is None:
            raise AttributeError('COSE_Key is not set')
        else:
            return self.key.key_bytes

    def encode(self,
               encrypt: bool = True,
               alg: Optional[CoseAlgorithm] = None,
               key: Optional[SymmetricKey] = None,
               crypto_params:
               List[Tuple[bool, Union[CoseAlgorithm, None], Union[SymmetricKey, None], List[Any]]] = None) -> list:

        if encrypt:
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(alg, key)]
        else:
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        # recursively encode/encrypt the recipients
        if len(self.recipients) > 0:
            recipients = CoseRecipient.recursive_encode(self.recipients, crypto_params)
            recipient.append(recipients)

        return recipient

    def encrypt(self, alg: Optional[CoseAlgorithm] = None, key: Optional[SymmetricKey] = None) -> bytes:
        """ Do key wrapping. """
        _alg = alg if alg is not None else self.phdr.get(HeaderKeys.ALG)
        _alg = _alg if _alg is not None else self.uhdr.get(HeaderKeys.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        if CoseAlgorithm.ECDH_SS_HKDF_512 <= _alg <= CoseAlgorithm.ECDH_ES_HKDF_256 or _alg == CoseAlgorithm.DIRECT:
            return b''

        try:
            _key = key.key_bytes if key is not None else self.key_bytes
        except AttributeError:
            raise AttributeError("No key specified.")

        return key_wrap(_key, self.payload)

    def decrypt(self, alg: Optional[CoseAlgorithm] = None, key: Optional[SymmetricKey] = None) -> bytes:
        """ Do key wrapping. """
        _alg = alg if alg is not None else self.phdr.get(HeaderKeys.ALG)
        _alg = _alg if _alg is not None else self.uhdr.get(HeaderKeys.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        if not (CoseAlgorithm.ECDH_SS_A256KW <= _alg <= CoseAlgorithm.ECDH_ES_HKDF_256 or CoseAlgorithm.ECDH_ES_A128KW
                or CoseAlgorithm.A256KW <= _alg <= CoseAlgorithm.A128KW):
            raise ValueError("algorithm is not a key wrapping algorithm")

        try:
            _key = key.key_bytes if key is not None else self.key_bytes
        except AttributeError:
            raise AttributeError("No key specified.")

        return key_unwrap(_key, self.payload)

    @singledispatchmethod
    @classmethod
    def derive_kek(cls, private_key, public_key: Optional[Union[EC2, OKP]] = None, alg: Optional[CoseAlgorithm] = None,
                   context: CoseKDFContext = None, salt: bytes = None, expose_secret: bool = False):
        raise NotImplementedError

    @derive_kek.register(EC2)
    @classmethod
    def _(cls, private_key: EC2, public_key: EC2 = None, alg: Optional[CoseAlgorithm] = None,
          context: CoseKDFContext = None,
          salt: bytes = None, expose_secret: bool = False):
        _ = salt

        try:
            crv = KEY_DERIVATION_CURVES[public_key.crv]()
        except KeyError:
            raise ValueError(f'Invalid curve: {public_key.crv}')

        # TODO: implement checks for the COSE_keys, correct curve, correct key operation, ..
        # TODO: move this logic to the crypto.py file
        d = ec.derive_private_key(int(hexlify(private_key.private_bytes), 16), crv, openssl.backend)
        p = ec.EllipticCurvePublicNumbers(
            int(hexlify(public_key.x), 16), int(hexlify(public_key.y), 16), crv).public_key(openssl.backend)

        secret, kek = ecdh_key_derivation(d, p, alg, int(context.supp_pub_info.key_data_length / 8), context.encode())

        if expose_secret:
            return secret, kek
        else:
            return kek

    @derive_kek.register(SymmetricKey)
    @classmethod
    def _(cls, private_key: SymmetricKey, public_key=None, alg: Optional[CoseAlgorithm] = None,
          context: CoseKDFContext = None, salt: bytes = None, expose_secret: bool = False):

        _ = public_key

        # TODO: implement checks for the COSE_keys, correct curve, correct key operation, ..
        kek = hmac_hkdf_key_derivation(
            alg=alg,
            shared_secret=private_key,
            length=int(context.supp_pub_info.key_data_length / 8),
            salt=salt,
            context=context.encode())

        if expose_secret:
            return private_key.private_bytes, kek
        else:
            return kek

    @derive_kek.register(OKP)
    @classmethod
    def _(cls, private_key: OKP, public_key: OKP = None, alg: Optional[CoseAlgorithm] = None,
          context: CoseKDFContext = None, salt: bytes = None, expose_secret: bool = False):
        _ = salt

        # TODO: move this logic to the crypto.py file
        # TODO: implement checks for the COSE_keys, correct curve, correct key operation, ..
        p = X25519PublicKey.from_public_bytes(public_key.public_bytes)
        d = X25519PrivateKey.from_private_bytes(private_key.private_bytes)

        secret, kek = x25519_key_derivation(d, p, alg, int(context.supp_pub_info.key_data_length / 8), context.encode())

        if expose_secret:
            return secret, kek
        else:
            return kek

    def __repr__(self) -> str:
        return f'<COSE_Recipient:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t recipients={self.recipients}>'
