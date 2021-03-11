from binascii import unhexlify, hexlify

from cose.keys.cosekey import CoseKey
from cose.keys.rsa import RSAKey
from cose.keys.keyparam import KpKty, KpKeyOps
from cose.keys.keytype import KtyEC2, KtyOKP


def test_rsakey_generation():
    trails = 4

    for length in [1024, 2048, 4096]:
        for _i in range(trails):
            sym_test = RSAKey.generate_key(length)
            sym_encoded = sym_test.encode()
            sym_decoded = CoseKey.decode(sym_encoded)
            assert sym_decoded.is_valid_key
