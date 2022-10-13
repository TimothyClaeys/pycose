import abc
import os
from typing import Optional, TYPE_CHECKING, List, Type, TypeVar

import cbor2

from pycose import headers, utils
from pycose.algorithms import \
    CoseAlgorithm, \
    Direct, \
    RsaesOaepSha512, \
    RsaesOaepSha256, \
    RsaesOaepSha1, \
    A128KW, \
    A192KW, \
    A256KW, \
    DirectHKDFAES256, \
    DirectHKDFSHA256, \
    EcdhEsHKDF256, \
    EcdhEsHKDF512, \
    EcdhEsA128KW, \
    EcdhEsA192KW, \
    EcdhEsA256KW, \
    EcdhSsHKDF256, \
    EcdhSsHKDF512, \
    EcdhSsA128KW, \
    EcdhSsA192KW, \
    EcdhSsA256KW
from pycose.exceptions import CoseException, CoseMalformedMessage, CoseIllegalAlgorithm
from pycose.keys.ec2 import EC2Key, EC2KpD
from pycose.keys.keyops import DeriveKeyOp, EncryptOp, DecryptOp, WrapOp, UnwrapOp, DeriveBitsOp
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.keys.rsa import RSAKey
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.context import CoseKDFContext, PartyInfo, SuppPubInfo
from pycose.messages.cosemessage import CoseMessage

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK
    from pycose.algorithms import _EncAlg

CBOR = bytes


class CoseRecipient(CoseMessage, metaclass=abc.ABCMeta):
    _RCPT_CLASSES = {}

    @classmethod
    def record_rc(cls, supported_algorithms: List[Type['CoseAlgorithm']]):
        """ Decorator to record all recipient classes dynamically. """

        def decorator(the_class):
            if not issubclass(the_class, CoseRecipient):
                raise ValueError("Can only decorate subclass of CoseRecipient")
            for alg_cls in supported_algorithms:
                if issubclass(alg_cls, CoseAlgorithm):
                    cls._RCPT_CLASSES[alg_cls] = the_class
            return the_class

        return decorator

    @classmethod
    def create_recipient(cls, recipient: list, allow_unknown_attributes: bool, context: str):
        if recipient[0] != b'':
            p_alg = cls._parse_header(cbor2.loads(recipient[0]), allow_unknown_attributes).get(headers.Algorithm)
        else:
            p_alg = None

        u_alg = cls._parse_header(recipient[1], allow_unknown_attributes).get(headers.Algorithm)

        if p_alg is not None:
            return cls._RCPT_CLASSES[p_alg].from_cose_obj(recipient, allow_unknown_attributes, context=context)
        elif u_alg is not None:
            return cls._RCPT_CLASSES[u_alg].from_cose_obj(recipient, allow_unknown_attributes, context=context)
        else:
            raise CoseException("No algorithm specified in recipient structure")

    @classmethod
    def has_recipient(cls, target: 'Recipient', recipients: List['Recipient']):
        found = False

        for r in recipients:
            if target is r:
                return True
            else:
                if len(r.recipients):
                    found = r.has_recipient(target, r.recipients)

        return found

    @classmethod
    def verify_recipients(cls, recipients: List['Recipient']) -> set:
        r_types = set()

        for r in recipients:
            r_types.add(r.__class__)

        if DirectEncryption in r_types and len(r_types) > 1:
            raise CoseException('When using DIRECT_ENCRYPTION mode, it must be the only mode used on the message')

        if DirectKeyAgreement in r_types and len(recipients) > 1:
            raise CoseException('When using DIRECT_KEY_AGREEMENT, it must be only one recipient in the message.')

        return r_types

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 recipients: Optional[List['Recipient']] = None,
                 *args,
                 **kwargs):
        """
        Create a COSE_Encrypt message.

        :param phdr: Protected header.
        :param uhdr: Unprotected header.
        :param payload: The payload of the COSE_Encrypt message.
        :param external_aad: External additional data (is authenticated by not included in the final message)
        :param recipients: An optional list of :class:`~pycose.messages.recipient.CoseRecipient` objects.
        """

        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, *kwargs)

        self._context = ''
        self._recipients = []
        self.recipients = recipients

    @property
    def cbor_tag(self):
        return None

    @property
    def recipients(self) -> List['Recipient']:
        return self._recipients

    @recipients.setter
    def recipients(self, recipients: List['Recipient']) -> None:

        if recipients is None:
            self._recipients = []
        else:
            for r in recipients:
                if not issubclass(type(r), CoseRecipient):
                    raise TypeError(f"Recipient must be a subclass of {CoseRecipient}")
                self._recipients.append(r)

    def get_kdf_context(self, algorithm: '_EncAlg') -> 'CoseKDFContext':
        """
        Create a COSE KDF context for use by the key derivation algorithms.

        :param algorithm: Specifies the target algorithm that will use the derived key.
        :returns: A CoseKDFContext object.
        """

        u_id = self.get_attr(headers.PartyUID)
        u_nonce = self.get_attr(headers.PartyUNonce)
        u_other = self.get_attr(headers.PartyUOther)
        u = PartyInfo(u_id, u_nonce, u_other)

        v_id = self.get_attr(headers.PartyVID)
        v_nonce = self.get_attr(headers.PartyVNonce)
        v_other = self.get_attr(headers.PartyVOther)
        v = PartyInfo(v_id, v_nonce, v_other)

        supp_pub = SuppPubInfo(algorithm.get_key_length(), self.phdr, self.local_attrs.get(headers.SuppPubOther, b''))
        supp_priv = self.local_attrs.get(headers.SuppPrivOther, b'')

        return CoseKDFContext(algorithm, supp_pub, u, v, supp_priv)

    def _setup_ephemeral_key(self, peer_key, optional_params: dict = None):
        self.key = EC2Key.generate_key(peer_key.crv, optional_params)

        if self.get_attr(headers.EphemeralKey) is not None:
            # public key was already set in the header bucket but we just generated a new ephemeral key.
            raise CoseException('Unrelated ephemeral public key found in COSE message header')
        else:
            # strip private bytes from key
            ephemeral_public_key = dict(self.key)
            del ephemeral_public_key[EC2KpD]

            # add to unprotected header
            self.uhdr_update({headers.EphemeralKey: ephemeral_public_key})


@CoseRecipient.record_rc([Direct, DirectHKDFSHA256, DirectHKDFAES256])
class DirectEncryption(CoseRecipient):

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool, *args, **kwargs) -> 'DirectEncryption':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.context = kwargs.get("context")

        if msg.payload != b"":
            raise CoseMalformedMessage("Recipient class DIRECT_ENCRYPTION must have a zero-length ciphertext.")
        if len(msg.recipients):
            raise CoseMalformedMessage("Recipient class DIRECT_ENCRYPTION cannot carry other recipients.")

        alg = msg.get_attr(headers.Algorithm)
        if alg == Direct and len(msg.phdr):
            raise CoseMalformedMessage(
                f"Recipient class DIRECT_ENCRYPTION with alg {alg} must have a zero-length protected header")

        return msg

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, context: str):
        self._context = context

    def encode(self, *args, **kwargs) -> list:
        alg = self.get_attr(headers.Algorithm)

        if alg == Direct and len(self.phdr) != 0:
            raise CoseException("Protected header must be empty")

        if alg is None:
            raise CoseException("Message must carry an algorithm parameter when using DIRECT_ENCRYPTION mode")

        if len(self.recipients):
            raise CoseException(f"Recipient class DIRECT_ENCRYPTION cannot carry recipients.")

        recipient = [self.phdr_encoded, self.uhdr_encoded, b'']

        return recipient

    def compute_cek(self, target_alg: 'CoseAlgorithm') -> Optional['SK']:
        alg = self.get_attr(headers.Algorithm)
        if alg == Direct:
            return None
        else:
            self.key.verify(SymmetricKey, algorithm=alg, key_ops=[DeriveKeyOp, DeriveBitsOp])
            _ = target_alg
            raise NotImplementedError()

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Recipient: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, {str(self.recipients)}]>'


@CoseRecipient.record_rc([A128KW, A192KW, A256KW,
                          RsaesOaepSha512, RsaesOaepSha256, RsaesOaepSha1])
class KeyWrap(CoseRecipient):
    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool, *args, **kwargs) -> 'KeyWrap':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.context = kwargs.get('context')

        # only AE algorithms supported thus the protected header must be empty
        alg = msg.get_attr(headers.Algorithm)
        if alg in {A128KW, A192KW, A256KW} and len(msg.phdr):
            raise CoseMalformedMessage(
                f"Recipient class KEY_WRAP with alg {alg} must have a zero-length protected header")

        if msg.payload == b'':
            raise CoseMalformedMessage(f'Recipient class KEY_WRAP must carry the encrypted CEK in its payload')

        msg.recipients = [CoseRecipient.create_recipient(r, allow_unknown_attributes, context='Rec_Recipient') for r in
                          msg.recipients]

        return msg

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, context: str):
        self._context = context

    def encode(self, *args, **kwargs) -> list:

        recipient = [self.phdr_encoded, self.uhdr_encoded, self.encrypt(kwargs.get('target_alg'))]

        if len(self.recipients):
            recipient.append([r.encode(*args, **kwargs) for r in self.recipients])

        return recipient

    def _compute_kek(self, target_alg: '_EncAlg', ops: 'str') -> bytes:

        if self.key is None:
            #  try to derive from this recipients' recipient list
            if not len(self.recipients):
                raise CoseException(f"No key found to {ops} the CEK")
            else:
                r_types = CoseRecipient.verify_recipients(self.recipients)

                if ops == 'encrypt':

                    if DirectKeyAgreement in r_types:
                        self.key = self.recipients[0].compute_cek(target_alg)

                    elif KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
                        key_bytes = os.urandom(self.get_attr(headers.Algorithm))
                        for r in self.recipients:
                            r.payload = key_bytes
                        self.key = SymmetricKey(k=key_bytes)
                    else:
                        raise CoseException('Unsupported COSE recipient class')
                else:
                    if DirectKeyAgreement in r_types or KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
                        self.key = self.recipients[0].decrypt(self.get_attr(headers.Algorithm))
                    else:
                        raise CoseException('Unsupported COSE recipient class')

        if self.key is None:
            raise CoseException("No key found to decrypt the CEK")

        return self.key.k

    def compute_cek(self, target_alg: '_EncAlg', ops: str) -> Optional['SK']:
        if ops == "encrypt":
            if self.payload == b'':
                return None
            else:
                return SymmetricKey(k=self.payload, optional_params={KpAlg: target_alg, KpKeyOps: [EncryptOp]})
        else:
            return SymmetricKey(k=self.decrypt(target_alg),
                                optional_params={KpAlg: target_alg, KpKeyOps: [DecryptOp]})

    def encrypt(self, target_alg: '_EncAlg') -> bytes:
        alg = self.get_attr(headers.Algorithm)

        if len(self.phdr):
            raise CoseException(f"Protected header must be empty when using an AE algorithm: {alg}")

        if alg is None:
            raise CoseException("The algorithm parameter should at least be included in the unprotected header")

        elif alg in {A128KW, A192KW, A256KW}:
            key_ops = [WrapOp, EncryptOp]
            kek = SymmetricKey(k=self._compute_kek(target_alg, ops='encrypt'),
                               optional_params={KpAlg: alg, KpKeyOps: key_ops})
            kek.verify(SymmetricKey, alg, [WrapOp, EncryptOp])
        elif alg in {RsaesOaepSha512, RsaesOaepSha256, RsaesOaepSha1}:
            kek = self.key
            kek.verify(RSAKey, alg, [WrapOp, EncryptOp])
        else:
            raise CoseIllegalAlgorithm(f"Algorithm {alg} for {self.__name__}")

        return alg.key_wrap(kek, self.payload)

    def decrypt(self, target_alg: '_EncAlg') -> bytes:
        alg = self.get_attr(headers.Algorithm)

        key_ops = [DecryptOp, UnwrapOp]

        if alg in {A128KW, A192KW, A256KW}:
            kek = SymmetricKey(k=self._compute_kek(target_alg, 'decrypt'),
                               optional_params={KpAlg: alg, KpKeyOps: key_ops})
            kek.verify(SymmetricKey, alg, [UnwrapOp, DecryptOp])
        elif alg in {RsaesOaepSha512, RsaesOaepSha256, RsaesOaepSha1}:
            kek = self.key
            kek.verify(RSAKey, alg, [UnwrapOp, DecryptOp])
        else:
            raise CoseException(f"Unsupported algorithm for key unwrapping: {alg}")

        return alg.key_unwrap(kek, self.payload)

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Recipient: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, {str(self.recipients)}]>'


@CoseRecipient.record_rc([EcdhEsHKDF256, EcdhEsHKDF512, EcdhSsHKDF256, EcdhSsHKDF512])
class DirectKeyAgreement(CoseRecipient):

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool, *args, **kwargs) -> 'DirectKeyAgreement':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.context = kwargs.get('context')

        alg = msg.get_attr(headers.Algorithm)
        if alg in {EcdhEsHKDF256, EcdhEsHKDF512} and msg.get_attr(headers.EphemeralKey) is None:
            raise CoseMalformedMessage(f'Recipient class {cls.__name__} must carry an ephemeral COSE key object')

        if len(msg.recipients):
            raise CoseMalformedMessage(f'Recipient class {cls.__name__} cannot carry more recipients')

        return msg

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, context: str):
        self._context = context

    def encode(self, *args, **kwargs) -> list:
        alg = self.get_attr(headers.Algorithm)

        if alg is None:
            raise CoseMalformedMessage("The algorithm parameter should be included in either the protected header or "
                                       "unprotected header")

        # static receiver key
        peer_key: 'EC2Key' = self.local_attrs.get(headers.StaticKey)

        if peer_key is None:
            raise CoseException("Static receiver key cannot be None. Should be configured in 'local_attrs' of the msg.")

        # if ephemeral and not set, generate ephemeral key pair
        if self.key is None:
            if alg in {EcdhEsHKDF256, EcdhEsHKDF512}:
                self._setup_ephemeral_key(peer_key)
            else:
                # alg uses a static sender
                raise CoseException("Static sender key cannot be None")

        if len(self.recipients) > 1:
            raise CoseMalformedMessage(f'Recipient class DIRECT_KEY_AGREEMENT cannot carry more recipients')

        # only the ephemeral sender key MUST be included in the header, for the static sender it is recommended by not
        # obligated
        if self.get_attr(headers.EphemeralKey) is None and alg in {EcdhEsHKDF512, EcdhEsHKDF256}:
            raise CoseMalformedMessage(f'Recipient class DIRECT_KEY_AGREEMENT must carry an ephemeral COSE key object')

        recipient = [self.phdr_encoded, self.uhdr_encoded, b'']

        if len(self.recipients):
            recipient.append([r.encode(*args, **kwargs) for r in self.recipients])

        return recipient

    def _compute_kek(self, target_alg: '_EncAlg', peer_key: 'EC2Key', local_key: 'EC2Key', kex_alg) -> bytes:

        return kex_alg.derive_kek(peer_key.crv, local_key, peer_key, self.get_kdf_context(target_alg))

    def compute_cek(self, target_alg: '_EncAlg', ops: str) -> 'SK':
        alg = self.get_attr(headers.Algorithm)

        if alg in {EcdhSsHKDF256, EcdhSsHKDF512, EcdhEsHKDF256, EcdhEsHKDF512}:
            if ops == "encrypt":
                peer_key = self.local_attrs.get(headers.StaticKey)
            else:
                if alg in {EcdhSsHKDF256, EcdhSsHKDF512}:
                    peer_key = self.get_attr(headers.StaticKey)
                else:
                    peer_key = self.get_attr(headers.EphemeralKey)
        else:
            raise CoseIllegalAlgorithm(f"Algorithm {alg} unsupported for {self.__name__}")

        if peer_key is None:
            raise CoseException("Unknown static receiver public key")

        peer_key.verify(EC2Key, alg, [DeriveKeyOp, DeriveBitsOp])
        self.key.verify(EC2Key, alg, [DeriveKeyOp, DeriveBitsOp])

        return SymmetricKey(k=self._compute_kek(target_alg, peer_key, self.key, alg),
                            optional_params={KpAlg: target_alg})

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Recipient: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, {str(self.recipients)}]>'


@CoseRecipient.record_rc([EcdhEsA128KW, EcdhEsA192KW, EcdhEsA256KW, EcdhSsA128KW, EcdhSsA192KW, EcdhSsA256KW])
class KeyAgreementWithKeyWrap(CoseRecipient):

    @classmethod
    def from_cose_obj(cls,
                      cose_obj: list,
                      allow_unknown_attributes: bool,
                      *args,
                      **kwargs) -> 'KeyAgreementWithKeyWrap':

        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.context = kwargs.get('context')

        if msg.payload == b'':
            raise CoseMalformedMessage(
                f'Recipient class KEY_AGREEMENT_WITH_KEY_WRAP must carry the encrypted CEK in its payload')

        msg.recipients = [CoseRecipient.create_recipient(r, allow_unknown_attributes, context='Rec_Recipient') for r in
                          msg.recipients]

        return msg

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, context: str):
        self._context = context

    def compute_cek(self, target_alg: '_EncAlg', ops: str) -> Optional['SK']:
        if ops == "encrypt":
            if self.payload == b'':
                return None
            else:
                return SymmetricKey(k=self.payload, optional_params={KpAlg: target_alg, KpKeyOps: [EncryptOp]})
        else:
            return SymmetricKey(k=self.decrypt(target_alg),
                                optional_params={KpAlg: target_alg, KpKeyOps: [DecryptOp]})

    def encode(self, *args, **kwargs) -> list:

        recipient = [self.phdr_encoded, self.uhdr_encoded,
                     self.encrypt((self.get_attr(headers.Algorithm)).get_key_wrap_func())]

        if len(self.recipients):
            recipient.append([r.encode(*args, **kwargs) for r in self.recipients])

        return recipient

    def _compute_kek(self, target_alg: '_EncAlg', peer_key: 'EC2Key', local_key: 'EC2Key', kex_alg) -> bytes:

        key_bytes = kex_alg.derive_kek(peer_key.crv, local_key, peer_key, self.get_kdf_context(target_alg))
        return key_bytes

    def encrypt(self, target_alg) -> bytes:
        # static receiver key
        _ = target_alg
        peer_key: 'EC2Key' = self.local_attrs.get(headers.StaticKey)

        if peer_key is None:
            raise CoseException("Static receiver key cannot be None. Should be configured in 'local_attrs' of the msg.")

        alg = self.get_attr(headers.Algorithm)

        if alg is None:
            raise CoseException("The algorithm parameter should at least be included in the unprotected header")

        # if ephemeral and not set, generate ephemeral key pair
        if self.key is None:
            if alg in {EcdhEsA128KW, EcdhEsA192KW, EcdhEsA256KW}:
                self._setup_ephemeral_key(peer_key)
            else:
                # alg uses a static sender
                raise CoseException("Static sender key cannot be None.")

        key_bytes = self._compute_kek((self.get_attr(headers.Algorithm)).get_key_wrap_func(), peer_key, self.key, alg)
        wrap_func = alg.get_key_wrap_func()

        return wrap_func.key_wrap(SymmetricKey(k=key_bytes, optional_params={KpAlg: alg, KpKeyOps: [DeriveKeyOp]}),
                                  self.payload)

    def decrypt(self, target_alg: '_EncAlg') -> bytes:
        alg = self.get_attr(headers.Algorithm)
        _ = target_alg

        if alg in {EcdhEsA256KW, EcdhEsA192KW, EcdhEsA128KW}:
            peer_key = self.get_attr(headers.EphemeralKey)
        elif alg in {EcdhSsA256KW, EcdhSsA192KW, EcdhSsA128KW}:
            peer_key = self.get_attr(headers.StaticKey)
        else:
            raise CoseIllegalAlgorithm(f"Algorithm {alg} unsupported for {self.__name__}")

        kek = SymmetricKey(k=self._compute_kek(alg.get_key_wrap_func(), peer_key, self.key, alg),
                           optional_params={KpAlg: alg, KpKeyOps: [UnwrapOp, DecryptOp]})

        kek.verify(SymmetricKey, alg, [UnwrapOp, DecryptOp])

        return alg.get_key_wrap_func().key_unwrap(kek, self.payload)

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Recipient: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, {str(self.recipients)}]>'


Recipient = TypeVar('Recipient', bound=CoseRecipient)
