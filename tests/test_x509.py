from binascii import unhexlify
from cose.headers import Algorithm
from cose import headers, algorithms
from cose.extensions.x509 import X5T


def test_x5t():
    data = b'doesntreallymatter'
    tprint = unhexlify(b'55563f4a5a4f4acc536e150f87f5cb6a6a22f7fe7bd27846bf5564440a090f57')

    head = X5T.from_certificate(algorithms.Sha256, data)
    assert head.alg == algorithms.Sha256
    assert head.thumbprint is not None

    assert head.encode() == [
        algorithms.Sha256,
        tprint
    ]
    assert head.matches(data)

    head2 = X5T.decode([-16, tprint])
    assert head2 == head
