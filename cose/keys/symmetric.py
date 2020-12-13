import os
from binascii import unhexlify
from enum import IntEnum
from typing import Optional, Union

import dataclasses
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import modes, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from dataclasses import dataclass

from cose.attributes.algorithms import CoseAlgorithms, config
from cose.attributes.context import CoseKDFContext
from cose.exceptions import CoseIllegalAlgorithm, CoseIllegalKeyOps
from cose.keys.cosekey import CoseKey, KTY, KeyOps


@CoseKey.record_kty(KTY.SYMMETRIC)
@dataclass(init=False)
class SymmetricKey(CoseKey):
    _k: Optional[bytes] = None

    class SymPrm(IntEnum):
        K = - 1

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self,
                 kid: Optional[bytes] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 k: Optional[bytes] = None):
        super().__init__(KTY.SYMMETRIC, kid, alg, key_ops, base_iv)
        self.k = k

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> 'SymmetricKey':
        """ Returns an initialized COSE_Key object of type OKP."""

        cose_key = cls(
            kid=cose_key_obj.get(cls.Common.KID),
            alg=cose_key_obj.get(cls.Common.ALG),
            key_ops=cose_key_obj.get(cls.Common.KEY_OPS),
            base_iv=cose_key_obj.get(cls.Common.BASE_IV),
            k=cose_key_obj.get(cls.SymPrm.K),
        )

        return cose_key

    @property
    def k(self) -> Optional[bytes]:
        return self._k

    @k.setter
    def k(self, new_k: Optional[bytes]) -> None:
        if type(new_k) is not bytes and new_k is not None:
            raise ValueError("symmetric key must be of type 'bytes'")
        self._k = new_k

    def encode(self, *argv):
        kws = ['_' + kw for kw in argv if self.SymPrm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.SymPrm[kw[1:].upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def encrypt(self, plaintext: bytes, aad: bytes, nonce: bytes, alg: Optional[CoseAlgorithms]) -> bytes:
        self._check_key_conf(alg, KeyOps.ENCRYPT)

        try:
            cipher = self._prepare_cipher()
            ciphertext = cipher.encrypt(nonce=nonce, data=plaintext, associated_data=aad)
        except KeyError as err:
            raise CoseIllegalAlgorithm(err)

        return ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes, nonce: bytes, alg: Optional[CoseAlgorithms] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.DECRYPT)

        try:
            cipher = self._prepare_cipher()
            plaintext = cipher.decrypt(nonce=nonce, data=ciphertext, associated_data=aad)
        except KeyError as err:
            raise CoseIllegalAlgorithm(err)

        return plaintext

    def _prepare_cipher(self):
        alg_cfg = config(CoseAlgorithms(self.alg))

        if alg_cfg.tag_length is not None:
            cipher: Union[AESGCM, AESCCM] = alg_cfg.primitive(self.k, tag_length=alg_cfg.tag_length)
        else:
            cipher = alg_cfg.primitive(self.k)

        return cipher

    def key_wrap(self, plaintext_key: bytes, alg: Optional[CoseAlgorithms] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.WRAP)

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseIllegalAlgorithm(err)

        if self.alg in {CoseAlgorithms.A128KW, CoseAlgorithms.A192KW, CoseAlgorithms.A256KW}:
            return alg_cfg.primitive.aes_key_wrap(self.k, plaintext_key, default_backend())
        elif self.alg == CoseAlgorithms.DIRECT:
            return b''
        else:
            raise CoseIllegalAlgorithm(f"Key wrap requires one of the following algorithms: \
            {(CoseAlgorithms.A256KW, CoseAlgorithms.A192KW, CoseAlgorithms.A128KW, CoseAlgorithms.DIRECT)}")

    def key_unwrap(self, wrapped_key: bytes, alg: Optional[CoseAlgorithms] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.UNWRAP)

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseIllegalAlgorithm(err)

        return alg_cfg.primitive.aes_key_unwrap(self.k, wrapped_key, default_backend())

    def compute_tag(self, to_be_maced: bytes, alg: Optional[CoseAlgorithms] = None) -> bytes:
        """
        Compute the MAC over the payload.

        :param to_be_maced: The payload over which the authentication tag will be calculated.
        :param alg: An optional CoseAlgorithm for computing the authentication tag.
        :return: The authentication tag.
        """

        self._check_key_conf(alg, KeyOps.MAC_CREATE)

        iv = unhexlify(b"".join([b"00"] * 16))

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseIllegalAlgorithm(err)

        if self.alg in {CoseAlgorithms.AES_MAC_128_128,
                        CoseAlgorithms.AES_MAC_128_64,
                        CoseAlgorithms.AES_MAC_256_64,
                        CoseAlgorithms.AES_MAC_256_128}:
            encryptor = Cipher(alg_cfg.primitive(self.k), modes.CBC(iv), backend=default_backend()).encryptor()

            while len(to_be_maced) % 16 != 0:
                to_be_maced += unhexlify(b"00")

            ciphertext = encryptor.update(to_be_maced) + encryptor.finalize()

            if alg_cfg.tag_length is not None:
                # truncate the result to the first 64 bits
                ciphertext = ciphertext[:-8]
                digest = ciphertext[-8:]
            else:
                digest = ciphertext[-16:]
        else:
            h = alg_cfg.primitive(self.k, alg_cfg.hash(), backend=default_backend())
            h.update(to_be_maced)
            digest = h.finalize()

            if CoseAlgorithms(self.alg) == CoseAlgorithms.HMAC_256_64:
                # truncate the result to the first 64 bits
                digest = digest[:8]

        return digest

    def verify_tag(self, tag: bytes, to_be_maced: bytes, alg: Optional[CoseAlgorithms] = None) -> bool:
        """
        Verify the MAC over the payload.

        :param tag: The authentication tag to verify.
        :param to_be_maced: The payload over which the tag was calculated.
        :param alg: An optional algorithm to be used when verifying the tag.
        :return: True for a valid tag or False for invalid tags.
        """

        self._check_key_conf(alg, KeyOps.MAC_VERIFY)

        self.key_ops = KeyOps.MAC_CREATE
        computed_tag = self.compute_tag(to_be_maced, alg)
        self.key_ops = KeyOps.MAC_VERIFY

        if tag != computed_tag:
            return False
        else:
            return True

    def hmac_key_derivation(self,
                            context: CoseKDFContext,
                            alg: Optional[CoseAlgorithms] = None,
                            salt: bytes = b'') -> bytes:
        """
        HMAC-based key derivation based on secret bytes and a CoseKDFContext object.

        :param context: A CoseKDFContext object which contains necessary input for the KDF algorithm.
        :param alg: An optional CoseAlgorithm parameter.
        :param salt: And optional salt parameter.
        :return: A cryptographic key with a length specified in the CoseKDFContext object.
        """

        self._check_key_conf(alg, KeyOps.DERIVE_KEY)

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseIllegalAlgorithm(err)

        derived_key = alg_cfg.kdf(algorithm=alg_cfg.hash(),
                                  length=int(context.supp_pub_info.key_data_length / 8),
                                  salt=salt,
                                  info=context.encode(),
                                  backend=default_backend()).derive(self.k)

        return derived_key

    @staticmethod
    def generate_key(algorithm: CoseAlgorithms, key_ops: KeyOps, key_len: int = 16) -> 'SymmetricKey':
        """
        Generate a random Symmetric COSE key object.

        :param algorithm: Specify the algorithm to use with the key object.
        :param key_ops: Choose a key operation.
        :param key_len: Symmetric key length in bytes, must be of size 16, 24 or 32.
        :raises ValueError: For invalid key lengths.
        :raises CoseIllegalKeyOps: When the key operation is not allowed on this key type.
        :returns: A COSE_key of type SymmetricKey.
        """

        if key_len not in [16, 24, 32]:
            raise ValueError("key_len must be of size 16, 24 or 32")

        if KeyOps(key_ops) not in [KeyOps.ENCRYPT, KeyOps.WRAP, KeyOps.DECRYPT, KeyOps.UNWRAP, KeyOps.MAC_CREATE,
                                   KeyOps.VERIFY]:
            raise CoseIllegalKeyOps(f"The key operation {key_ops} is invalid for this key object.")

        return SymmetricKey(
            alg=CoseAlgorithms(algorithm),
            key_ops=KeyOps(key_ops),
            k=os.urandom(key_len)
        )

    def __repr__(self):
        hdr = '<COSE_Key(Symmetric): {'
        output = [f'{k[1:]}: {v.__repr__()}' for k, v in dataclasses.asdict(self).items() if v is not None]
        return hdr + ", ".join(output) + '}>'
