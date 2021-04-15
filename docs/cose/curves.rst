COSE Curves
===========

Overview
--------

All :class:`~cose.curves.CoseCurve` classes have a `fullname` and `identifier` attribute. The full list with COSE
curves and their identifiers can be found at the IANA registry.

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.curves import Ed25519
    >>> from cose.keys import OKPKey, EC2Key

    >>> key = OKPKey.generate_key(crv=Ed25519)
    >>> key.crv.fullname
    'ED25519'

    >>> key = EC2Key.generate_key(crv="P_256")
    >>> key.crv.identifier
    1


API
---

.. module:: cose.curves

.. autoclass:: Reserved

.. autoclass:: P256

.. autoclass:: P384

.. autoclass:: P521

.. autoclass:: X25519

.. autoclass:: X448

.. autoclass:: Ed448

.. autoclass:: Ed25519

.. autoclass:: SECP256K1

