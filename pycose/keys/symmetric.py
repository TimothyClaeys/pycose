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
from pycose.exceptions import CoseUnknownAlgorithm, CoseIllegalKeyOps, CoseInvalidTag
from pycose.keys.cosekey import CoseKey, KTY, KeyOps


@CoseKey.record_kty(KTY.SYMMETRIC)
@dataclass(init=False)
class SymmetricKey(CoseKey):
    k: Optional[bytes] = None

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
    def key_bytes(self):
        return self.k

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

    def encrypt(self, plaintext: bytes, aad: bytes, nonce: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.ENCRYPT)

        try:
            algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
            if algorithm.tag_length is not None:
                cipher: Union[AESGCM, AESCCM] = algorithm.primitive(self.k, tag_length=algorithm.tag_length)
            else:
                cipher = algorithm.primitive(self.k)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
        except KeyError as err:
            raise CoseUnknownAlgorithm(err)

        return ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes, nonce: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.DECRYPT)

        try:
            algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
            if algorithm.tag_length is not None:
                cipher: Union[AESGCM, AESCCM] = algorithm.primitive(self.key, tag_length=algorithm.tag_length)
            else:
                cipher = algorithm.primitive(self.key)
            plaintext = cipher.decrypt(nonce, ciphertext, aad)
        except KeyError as err:
            raise CoseUnknownAlgorithm(err)

        return plaintext

    def key_wrap(self, plaintext_key: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.WRAP)

        try:
            algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
        except KeyError as err:
            raise CoseUnknownAlgorithm(err)

        return algorithm.primitive.aes_key_wrap(self.k, plaintext_key, openssl.backend)

    def key_unwrap(self, wrapped_key: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        self._check_key_conf(alg, KeyOps.UNWRAP)

        try:
            algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
        except KeyError as err:
            raise CoseUnknownAlgorithm(err)

        return algorithm.primitive.aes_key_unwrap(self.k, wrapped_key, openssl.backend)

    def calc_tag_wrapper(self, to_be_maced: bytes, alg: Optional[AlgorithmIDs] = None) -> bytes:
        """ Calculate the MAC over the payload """

        self._check_key_conf(alg, KeyOps.MAC_CREATE)

        iv = unhexlify(b"".join([b"00"] * 16))

        try:
            algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
            encryptor = Cipher(algorithm.primitive(self.k), modes.CBC(iv), backend=openssl.backend).encryptor()

            padded = False
            while len(to_be_maced) % 16 != 0:
                to_be_maced += unhexlify(b"00")
                padded = True

            ciphertext = encryptor.update(to_be_maced) + encryptor.finalize()

            if padded:
                ciphertext = ciphertext[:-8]

            if algorithm.tag_length is not None:
                # truncate the result to the first 64 bits
                digest = ciphertext[-8:]
            else:
                digest = ciphertext[-16:]
        except KeyError:
            try:
                algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
                h = algorithm.primitive(self.k, algorithm.hash, backend=openssl.backend)
                h.update(to_be_maced)
                digest = h.finalize()

                if algorithm == AlgorithmIDs.HMAC_256_64:
                    # truncate the result to the first 64 bits
                    digest = digest[:8]

            except KeyError as e:
                raise CoseUnknownAlgorithm(e)

        return digest

    def verify_tag_wrapper(self, tag: bytes, to_be_maced: bytes, alg: Optional[AlgorithmIDs] = None) -> bool:
        """ Verify the MAC over the payload """

        self._check_key_conf(alg, KeyOps.MAC_VERIFY)

        self.key_ops = KeyOps.MAC_CREATE
        computed_tag = self.calc_tag_wrapper(to_be_maced, alg)
        self.key_ops = KeyOps.MAC_VERIFY

        if tag != computed_tag:
            raise CoseInvalidTag(f"Invalid authentication tag: {tag} != {computed_tag}")
        return True

    def hmac_key_derivation(self, alg: Optional[AlgorithmIDs] = None, salt: bytes = None,
                            context: CoseKDFContext = b'') -> bytes:

        self._check_key_conf(alg, KeyOps.DERIVE_KEY)
        algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value

        derived_key = algorithm.primitive(algorithm=algorithm.hash,
                                          length=int(context.supp_pub_info.key_data_length / 8),
                                          salt=salt,
                                          info=context.encode(),
                                          backend=openssl.backend).derive(self.key.k)

        return derived_key

    def _check_key_conf(self, algorithm: AlgorithmIDs, key_operation: KeyOps):
        """ Helper function that checks the configuration of the COSE key object. """

        if self.alg is not None and algorithm is not None and self.alg != algorithm:
            raise ValueError("COSE key algorithm does not match with parameter 'algorithm'")

        if algorithm is not None:
            self.alg = algorithm

        if self.key_ops is not None and key_operation is not None and self.key_ops != key_operation:
            raise CoseIllegalKeyOps(f"COSE key operation does not match with {key_operation}")

        if key_operation is not None:
            self.key_ops = key_operation
