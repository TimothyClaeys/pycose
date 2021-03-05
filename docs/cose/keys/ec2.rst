EC2 Key
=======

The COSE Key object defines a way to hold a single key object. The EC2 key structure is defined for elliptic curve keys.
There is another COSE key structure available for elliptic curve keys the OKP COSE key. The EC2 key uses both an
x-coordinate and a y-coordinate, potentially with point compression.

.. module:: cose.keys.ec2

.. autoclass:: EC2
    :members:
    :inherited-members:
    :exclude-members: record_kty
