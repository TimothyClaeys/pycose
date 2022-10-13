COSE Curves
===========

Overview
--------

All :class:`~pycose.curves.CoseCurve` classes have a `fullname`, `identifier`, `curve_obj`, `key_type`, and `size` attribute. The full list with COSE
curves and their identifiers can be found at the IANA registry.

.. doctest::
    :pyversion: >= 3.6

    >>> from pycose.keys.curves import Ed25519
    >>> from pycose.keys import OKPKey

    >>> key = OKPKey.generate_key(crv=Ed25519)
    >>> key.crv.fullname
    'ED25519'

    >>> key.crv.identifier
    6

    >>> key.crv.curve_obj
    <class 'cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey'>

    >>> key.crv.key_type
    <class 'pycose.keys.keytype.KtyOKP'>

    >>> key.crv.size
    32


API
---

.. module:: pycose.keys.curves

.. autoclass:: Reserved

.. autoclass:: P256

.. autoclass:: P384

.. autoclass:: P521

.. autoclass:: X25519

.. autoclass:: X448

.. autoclass:: Ed25519

.. autoclass:: Ed448

.. autoclass:: SECP256K1
