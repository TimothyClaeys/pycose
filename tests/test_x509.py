from binascii import unhexlify
from pycose import algorithms
from pycose.algorithms import Sha256Trunc64
from pycose.extensions.x509 import X5T


def test_x5t():
    data = b'5864c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b05' \
           b'34b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2'

    tprint = unhexlify(b'6844078a53f312f5')

    head = X5T.from_certificate(Sha256Trunc64, unhexlify(data), True)
    assert head.alg == algorithms.Sha256Trunc64
    assert head.thumbprint is not None

    assert head.encode() == [
        algorithms.Sha256Trunc64,
        tprint
    ]
    assert head.matches(unhexlify(data), True)

    head2 = X5T.decode([-15, tprint])
    assert head2 == head
