EC2 Key
=======

The COSE Key object defines a way to hold a single key object. The EC2 key structure is defined for elliptic curve keys.
There is another COSE key structure available for elliptic curve keys the OKP COSE key. The EC2 key uses both an
x-coordinate and a y-coordinate, potentially with point compression.

.. doctest::

    >>> from cose import EC2, CoseAlgorithms, KeyOps, CoseEllipticCurves

    # generates a random EC2 COSE key for a given curve.
    >>> ec2key = EC2.generate_key(CoseEllipticCurves.P_256)
    >>> type(ec2key) == EC2
    True

    # create a signature
    >>> to_be_signed = b'signed_message'
    >>> signature = ec2key.sign(to_be_signed, alg=CoseAlgorithms.ES256)

    # verify the signature
    >>> ec2key.key_ops = KeyOps.VERIFY
    >>> ec2key.verify(to_be_signed, signature)
    True

.. module:: cose.keys.ec2

.. autoclass:: EC2
    :members:
    :inherited-members:
    :exclude-members: record_kty
