import sys
from typing import Union, List, Optional, Tuple

from dataclasses import dataclass, field

from pycose import CoseMessage
from pycose.algorithms import AlgorithmIDs
from pycose.context import CoseKDFContext
from pycose.exceptions import CoseIllegalKeyType, CoseInvalidAlgorithm
from pycose.keys.cosekey import EllipticCurveTypes, CK
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP
from pycose.keys.symmetric import SymmetricKey

if sys.version_info.minor < 8:
    from singledispatchmethod import singledispatchmethod
else:
    from functools import singledispatchmethod


@dataclass
class RcptParams:
    key: SymmetricKey
    alg: Optional[AlgorithmIDs] = None
    params: List['RcptParams'] = field(default_factory=list)
    encrypt_or_mac: bool = True


class CoseRecipient(CoseMessage):

    @classmethod
    def recursive_encode(cls, recipients: List['CoseRecipient'], enc_params: List[RcptParams]) -> list:
        """ Recursively encode/encrypt the recipients """

        recipients = [r.encode(p) for r, p in zip(recipients, enc_params)]

        return recipients

    @classmethod
    def from_recipient_obj(cls, recipient_obj: list) -> list:
        msg = super().from_cose_obj(recipient_obj)

        try:
            recipient_list = recipient_obj.pop(0)
            msg.recipient_list = [CoseRecipient.from_recipient_obj(r) for r in recipient_list]
        except IndexError:
            msg.recipient_list = None

        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 recipients: Optional[List] = None):

        super().__init__(phdr=phdr, uhdr=uhdr, payload=payload)

        self.recipients = [] if recipients is None else recipients

    def encode(self, parameters: RcptParams) -> list:
        if parameters.encrypt_or_mac:
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(parameters.alg, parameters.key)]
        else:
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        # recursively encode/encrypt the recipients
        if len(self.recipients) == len(parameters.params):
            if len(self.recipients) > 0:
                recipient.append(CoseRecipient.recursive_encode(self.recipients, parameters.params))
        else:
            raise ValueError("List with cryptographic parameters should have the same length as the recipient list.")

        return recipient

    def encrypt(self, alg: AlgorithmIDs, key: SymmetricKey) -> bytes:
        """ Key wrapping. """

        self._sanitize_args(key, alg)

        return key.key_wrap(self.payload, alg=alg)

    def decrypt(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None) -> bytes:
        """ Key unwrapping. """

        self._sanitize_args(key, alg)

        return key.key_unwrap(self.payload, alg=alg)

    @singledispatchmethod
    @classmethod
    def derive_kek(cls,
                   private_key: CK,
                   public_key: Optional[Union[EC2, OKP]] = None,
                   alg: Optional[AlgorithmIDs] = None,
                   context: CoseKDFContext = None,
                   curve: Optional[EllipticCurveTypes] = None,
                   salt: bytes = b'',
                   expose_secret: bool = False) -> Union[Tuple[bytes, bytes], bytes]:
        """ Derive the Key Encryption Key (KEK) which protects the CEK (Content Encryption Key) """

        raise NotImplementedError

    @derive_kek.register(EC2)
    @classmethod
    def _(cls,
          private_key: EC2,
          public_key: EC2,
          alg: Optional[AlgorithmIDs] = None,
          context: Optional[CoseKDFContext] = None,
          curve: Optional[EllipticCurveTypes] = None,
          salt: bytes = b'',
          expose_secret: bool = False) -> Union[Tuple[bytes, bytes], bytes]:
        _ = salt

        secret, kek = private_key.ecdh_key_derivation(public_key, context, alg, curve)

        if expose_secret:
            return secret, kek
        else:
            return kek

    @derive_kek.register(SymmetricKey)
    @classmethod
    def _(cls,
          private_key: SymmetricKey,
          public_key=None,
          alg: Optional[AlgorithmIDs] = None,
          context: CoseKDFContext = None,
          curve=None,
          salt: bytes = b'',
          expose_secret: bool = False):

        _ = public_key
        _ = curve

        kek = private_key.hmac_key_derivation(context, alg, salt)

        if expose_secret:
            return private_key.private_bytes, kek
        else:
            return kek

    @derive_kek.register(OKP)
    @classmethod
    def _(cls,
          private_key: OKP,
          public_key: OKP,
          alg: Optional[AlgorithmIDs] = None,
          context: CoseKDFContext = None,
          curve: Optional[EllipticCurveTypes] = None,
          salt: bytes = None,
          expose_secret: bool = False):
        _ = salt

        secret, kek = private_key.x25519_key_derivation(public_key, context, alg, curve)

        if expose_secret:
            return secret, kek
        else:
            return kek

    @classmethod
    def _sanitize_args(cls, key: SymmetricKey, alg: Optional[AlgorithmIDs] = None) -> None:
        """ Sanitize parameters for encryption/decryption algorithms. """

        if key is None:
            raise CoseIllegalKeyType("COSE Key cannot be None")

        if key.alg is None and alg is None:
            raise CoseInvalidAlgorithm("COSE algorithm cannot be None")

    def __repr__(self) -> str:
        return f'<COSE_Recipient:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t recipients={self.recipients}>'
