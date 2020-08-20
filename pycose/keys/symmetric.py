from binascii import hexlify, unhexlify
from enum import IntEnum
from typing import Optional, Union

import dataclasses
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import modes, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from dataclasses import dataclass

from pycose.algorithms import AlgID2Crypto, AlgoParam, AlgorithmIDs
from pycose.context import CoseKDFContext
from pycose.exceptions import CoseInvalidAlgorithm, CoseInvalidTag
from pycose.keys.cosekey import CoseKey, KTY, KeyOps


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

    @property
    def k(self) -> Optional[bytes]:
        return self._k

    @k.setter
    def k(self, new_k: Optional[bytes]) -> None:
        if type(new_k) is not bytes and new_k is not None:
            raise ValueError("symmetric key must be of type 'bytes'")
        self._k = new_k

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> dict:
        """Returns an initialized COSE_Key object."""

        key_obj = super().from_cose_key_obj(cose_key_obj)

        if cls.SymPrm.K in cose_key_obj:
            key_obj[cls.SymPrm.K] = hexlify(key_obj[cls.SymPrm.K])

        return key_obj

    def encode(self, *argv):
        kws = [kw for kw in argv if self.SymPrm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.SymPrm[kw.upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(SymmetricKey)>']
        output.extend(self._base_repr(k, v) if k not in [-1] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)

    def encrypt(self, plaintext: bytes, aad: bytes, nonce: bytes, alg: Optional[AlgorithmIDs]) -> bytes:
        self._check_key_conf(alg, KeyOps.ENCRYPT)

        try:
            cipher = self._prepare_cipher()
            ciphertext = cipher.encrypt(nonce=nonce, data=plaintext, associated_data=aad)
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        return ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes, nonce: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.DECRYPT)

        try:
            cipher = self._prepare_cipher()
            plaintext = cipher.decrypt(nonce=nonce, data=ciphertext, associated_data=aad)
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        return plaintext

    def _prepare_cipher(self):
        alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

        algorithm: AlgoParam = AlgID2Crypto[alg].value

        if algorithm.tag_length is not None:
            cipher: Union[AESGCM, AESCCM] = algorithm.primitive(self.k, tag_length=algorithm.tag_length)
        else:
            cipher = algorithm.primitive(self.k)

        return cipher

    def key_wrap(self, plaintext_key: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.WRAP)

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        if self.alg in {AlgorithmIDs.A128KW, AlgorithmIDs.A192KW, AlgorithmIDs.A256KW}:
            return algorithm.primitive.aes_key_wrap(self.k, plaintext_key, openssl.backend)
        elif self.alg == AlgorithmIDs.DIRECT:
            return b''
        else:
            raise CoseInvalidAlgorithm(f"Key wrap requires one of the following algorithms: \
            {(AlgorithmIDs.A256KW, AlgorithmIDs.A192KW, AlgorithmIDs.A128KW, AlgorithmIDs.DIRECT)}")

    def key_unwrap(self, wrapped_key: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.UNWRAP)

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        return algorithm.primitive.aes_key_unwrap(self.k, wrapped_key, openssl.backend)

    def compute_tag(self, to_be_maced: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        """ Calculate the MAC over the payload """

        self._check_key_conf(alg, KeyOps.MAC_CREATE)

        iv = unhexlify(b"".join([b"00"] * 16))

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        if self.alg in {AlgorithmIDs.AES_MAC_128_128,
                        AlgorithmIDs.AES_MAC_128_64,
                        AlgorithmIDs.AES_MAC_256_64,
                        AlgorithmIDs.AES_MAC_256_128}:
            encryptor = Cipher(algorithm.primitive(self.k), modes.CBC(iv), backend=openssl.backend).encryptor()

            while len(to_be_maced) % 16 != 0:
                to_be_maced += unhexlify(b"00")

            ciphertext = encryptor.update(to_be_maced) + encryptor.finalize()

            if algorithm.tag_length is not None:
                # truncate the result to the first 64 bits
                ciphertext = ciphertext[:-8]
                digest = ciphertext[-8:]
            else:
                digest = ciphertext[-16:]
        else:
            h = algorithm.primitive(self.k, algorithm.hash(), backend=openssl.backend)
            h.update(to_be_maced)
            digest = h.finalize()

            if AlgorithmIDs[alg] == AlgorithmIDs.HMAC_256_64:
                # truncate the result to the first 64 bits
                digest = digest[:8]

        return digest

    def verify_tag(self, tag: bytes, to_be_maced: bytes, alg: Optional[AlgorithmIDs] = None) -> bool:
        """ Verify the MAC over the payload """

        self._check_key_conf(alg, KeyOps.MAC_VERIFY)

        self.key_ops = KeyOps.MAC_CREATE
        computed_tag = self.compute_tag(to_be_maced, alg)
        self.key_ops = KeyOps.MAC_VERIFY

        if tag != computed_tag:
            raise CoseInvalidTag(f"Invalid authentication tag: {tag} != {computed_tag}")
        return True

    def hmac_key_derivation(self,
                            context: CoseKDFContext,
                            alg: Optional[AlgorithmIDs] = None,
                            salt: bytes = b'') -> bytes:

        self._check_key_conf(alg, KeyOps.DERIVE_KEY)

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        derived_key = algorithm.key_derivation(algorithm=algorithm.hash(),
                                               length=int(context.supp_pub_info.key_data_length / 8),
                                               salt=salt,
                                               info=context.encode(),
                                               backend=openssl.backend).derive(self.k)

        return derived_key
