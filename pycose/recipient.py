import sys
from typing import Union, List, Optional, Any, Tuple

from pycose import CoseMessage
from pycose.algorithms import AlgorithmIDs
from pycose.context import CoseKDFContext
from pycose.cosebase import HeaderKeys
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP
from pycose.keys.symmetric import SymmetricKey

if sys.version_info.minor < 8:
    from singledispatchmethod import singledispatchmethod
else:
    from functools import singledispatchmethod


class CoseRecipient(CoseMessage):

    @classmethod
    def recursive_encode(
            cls,
            recipients: List['CoseRecipient'],
            crypto_params:
            Tuple[Tuple[bool, Optional[AlgorithmIDs], Optional[SymmetricKey], Optional[Tuple[Any]]]] = None) -> list:
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

    def encode(self,
               encrypt: bool = True,
               alg: Optional[AlgorithmIDs] = None,
               key: Optional[SymmetricKey] = None,
               crypto_params:
               List[Tuple[bool, Union[AlgorithmIDs, None], Union[SymmetricKey, None], List[Any]]] = None) -> list:

        if encrypt:
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.encrypt(alg, key)]
        else:
            recipient = [self.encode_phdr(), self.encode_uhdr(), self.payload]

        # recursively encode/encrypt the recipients
        if len(self.recipients) > 0:
            recipients = CoseRecipient.recursive_encode(self.recipients, crypto_params)
            recipient.append(recipients)

        return recipient

    def encrypt(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None) -> bytes:
        """ Key wrapping. """

        alg, key = self._get_enc_params(alg, key)
        return self.key.key_wrap(self.payload, alg=alg)

    def decrypt(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None) -> bytes:
        """ Key unwrapping. """

        alg, key = self._get_enc_params(alg, key)
        return self.key.key_unwrap(self.payload, alg=alg)

    @singledispatchmethod
    @classmethod
    def derive_kek(cls, private_key, public_key: Optional[Union[EC2, OKP]] = None, alg: Optional[AlgorithmIDs] = None,
                   context: CoseKDFContext = None, salt: bytes = None, expose_secret: bool = False):
        raise NotImplementedError

    @derive_kek.register(EC2)
    @classmethod
    def _(cls, private_key: EC2, public_key: Optional[EC2] = None, alg: Optional[AlgorithmIDs] = None,
          context: Optional[CoseKDFContext] = None,
          salt: bytes = None, expose_secret: bool = False):
        _ = salt

        secret, kek = private_key.ecdh_key_derivation(public_key, alg, context)

        if expose_secret:
            return secret, kek
        else:
            return kek

    @derive_kek.register(SymmetricKey)
    @classmethod
    def _(cls, private_key: SymmetricKey, public_key=None, alg: Optional[AlgorithmIDs] = None,
          context: CoseKDFContext = None, salt: bytes = None, expose_secret: bool = False):

        _ = public_key

        kek = private_key.hmac_key_derivation(alg, salt, context)

        if expose_secret:
            return private_key.private_bytes, kek
        else:
            return kek

    @derive_kek.register(OKP)
    @classmethod
    def _(cls, private_key: OKP, public_key: OKP = None, alg: Optional[AlgorithmIDs] = None,
          context: CoseKDFContext = None, salt: bytes = None, expose_secret: bool = False):
        _ = salt

        secret, kek = private_key.x25519_key_derivation(public_key, alg, context)

        if expose_secret:
            return secret, kek
        else:
            return kek

    def _get_enc_params(self, alg: Optional[AlgorithmIDs] = None, key: Optional[SymmetricKey] = None
                        ) -> Tuple[AlgorithmIDs, SymmetricKey]:
        """ Do key wrapping. """
        _alg = alg if alg is not None else self.phdr.get(HeaderKeys.ALG)
        _alg = _alg if _alg is not None else self.uhdr.get(HeaderKeys.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        if not (AlgorithmIDs.ECDH_SS_A256KW <= _alg <= AlgorithmIDs.ECDH_ES_HKDF_256 or AlgorithmIDs.ECDH_ES_A128KW
                or AlgorithmIDs.A256KW <= _alg <= AlgorithmIDs.A128KW):
            raise ValueError("algorithm is not a key wrapping algorithm")

        try:
            _key = key if key is not None else self.key
        except AttributeError:
            raise AttributeError("No key specified.")

        return _alg, _key

    def _get_kek_derive_params(self,
                               alg: Optional[AlgorithmIDs],
                               key: Optional[Union[EC2, OKP]]) -> Tuple[Union[EC2, OKP], AlgorithmIDs]:
        """ Analyze the COSE headers and provided data and extract the correct key derivation parameters. """

        try:
            _key = key if key is not None else self.key
        except AttributeError:
            raise AttributeError("No key specified.")

        # search in protected headers
        _alg = alg if alg is not None else self.phdr.get(HeaderKeys.ALG)

        # search in unprotected headers
        _alg = _alg if _alg is not None else self.uhdr.get(HeaderKeys.ALG)

        if _alg is None:
            raise AttributeError('No algorithm specified.')

        return _key, _alg

    def __repr__(self) -> str:
        return f'<COSE_Recipient:\n' \
               f'\t phdr={self._phdr}\n' \
               f'\t uhdr={self._uhdr}\n' \
               f'\t payload={self._payload}\n' \
               f'\t recipients={self.recipients}>'
