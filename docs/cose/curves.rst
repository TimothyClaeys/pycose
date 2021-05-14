COSE Curves
===========

Overview
--------

All :class:`~cose.curves.CoseCurve` classes have a `fullname`, `identifier`, `curve_obj`, `key_type`, and `size` attribute. The full list with COSE
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
