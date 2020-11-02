from binascii import unhexlify

from pytest import mark

from cose import CoseAlgorithms
from cose.extensions.x509 import X5T

certificate = "47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db" \
              "78974c271579b01633a3ef6271be5c225eb28f9cf6180b5a6af31e80209a085cfbf95f3fdcf9b18b693d6c0e0d0ffb8e3f9a32" \
              "a50859ecd0bfcff2c218"


@mark.parametrize("alg_id, cert, result",
                  [
                      (CoseAlgorithms.SHA_256_64,
                       unhexlify(certificate),
                       [-15, unhexlify("FC79990F2431A3F5")])
                  ], ids=["base_x5t_encoding_test"])
def test_x5t_encoding(alg_id, cert, result):
    x5t = X5T(alg_id, cert)
    assert x5t.encode() == result
