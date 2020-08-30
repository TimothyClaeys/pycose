from typing import List, Union

from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.hashes import Hash

from pycose.algorithms import CoseAlgorithms, config
from pycose.exceptions import CoseInvalidAlgorithm


class X5Bag:
    def __init__(self, certificates: Union[List[bytes], bytes]):
        if isinstance(certificates, list) and len(certificates) == 1:
            self.certificates = certificates[0]
        else:
            self.certificates = certificates

    def encode(self) -> Union[bytes, List[bytes]]:
        return self.certificates


class X5T:
    def __init__(self, alg_id: 'CoseAlgorithms', certificate: bytes):
        self.alg = alg_id
        self.certificate = certificate

    def compute_hash(self) -> bytes:
        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        h = Hash(algorithm=alg_cfg.hash(), backend=openssl.backend)
        h.update(self.certificate)
        digest = h.finalize()

        if alg_cfg.tag_length is not None:
            digest = digest[:8]

        return digest

    def encode(self):
        return [self.alg, self.compute_hash()]


class X5U:
    def __init__(self, uri: str):
        self.uri = uri

    def encode(self):
        return self.uri


class X5Chain:
    def __init__(self, cert_chain: Union[List[bytes], bytes], verify: bool = False):
        if isinstance(cert_chain, list) and len(cert_chain) == 1:
            self.cert_chain = cert_chain[0]
        else:
            self.cert_chain = cert_chain

        if verify:
            self.verify_chain()

    def verify_chain(self):
        # TODO: verify certificate chain
        pass

    def encode(self) -> Union[bytes, List[bytes]]:
        return self.cert_chain
