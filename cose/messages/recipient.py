import sys
from typing import Union, List, Optional, Tuple, TYPE_CHECKING

from dataclasses import dataclass, field

from cose import CoseMessage
from cose.exceptions import CoseIllegalKeyType
from cose.keys.ec import EC2
from cose.keys.okp import OKP
from cose.keys.symmetric import SymmetricKey

if sys.version_info.minor < 8:
    from singledispatchmethod import singledispatchmethod
else:
    from functools import singledispatchmethod

if TYPE_CHECKING:
    from cose.attributes.context import CoseKDFContext
    from cose.attributes.algorithms import CoseAlgorithms
    from cose.keys.cosekey import CoseEllipticCurves, CK


@dataclass
class RcptParams:
    key: SymmetricKey
    alg: Optional['CoseAlgorithms'] = None
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
            msg.recipients = [CoseRecipient.from_recipient_obj(r) for r in recipient_list]
        except IndexError:
            msg.recipients = []

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
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(key=parameters.key, alg=parameters.alg)]
        else:
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        # recursively encode/encrypt the recipients
        if len(self.recipients) == len(parameters.params):
            if len(self.recipients) > 0:
                recipient.append(CoseRecipient.recursive_encode(self.recipients, parameters.params))
        else:
            raise ValueError("List with cryptographic parameters should have the same length as the recipient list.")

        return recipient

    def encrypt(self, key: SymmetricKey, alg: Optional['CoseAlgorithms'] = None) -> bytes:
        """ Key wrapping. """

        if key is None:
            raise CoseIllegalKeyType("COSE Key cannot be None")

        return key.key_wrap(self.payload, alg=alg)

    def decrypt(self, key: SymmetricKey, alg: Optional['CoseAlgorithms'] = None) -> bytes:
        """ Key unwrapping. """

        if key is None:
            raise CoseIllegalKeyType("COSE Key cannot be None")

        return key.key_unwrap(self.payload, alg=alg)

    @singledispatchmethod
    @classmethod
    def derive_kek(cls,
                   private_key: 'CK',
                   public_key: Optional[Union[EC2, OKP]] = None,
                   alg: Optional['CoseAlgorithms'] = None,
                   context: 'CoseKDFContext' = None,
                   curve: Optional['CoseEllipticCurves'] = None,
                   salt: bytes = b'',
                   expose_secret: bool = False) -> Union[Tuple[bytes, bytes], bytes]:
        """ Derive the Key Encryption Key (KEK) which protects the CEK (Content Encryption Key) """

        raise NotImplementedError

    @derive_kek.register(EC2)
    @classmethod
    def _(cls,
          private_key: EC2,
          public_key: EC2,
          alg: Optional['CoseAlgorithms'] = None,
          context: Optional['CoseKDFContext'] = None,
          curve: Optional['CoseEllipticCurves'] = None,
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
          alg: Optional['CoseAlgorithms'] = None,
          context: 'CoseKDFContext' = None,
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
          alg: Optional['CoseAlgorithms'] = None,
          context: 'CoseKDFContext' = None,
          curve: Optional['CoseEllipticCurves'] = None,
          salt: bytes = None,
          expose_secret: bool = False):
        _ = salt

        secret, kek = private_key.x25519_key_derivation(public_key, context, alg, curve)

        if expose_secret:
            return secret, kek
        else:
            return kek

    def __repr__(self) -> str:
        return \
            f'<COSE_Recipient: [{self._phdr}, {self._uhdr}, {CoseMessage._truncate(self._payload)}, {self.recipients}]>'
