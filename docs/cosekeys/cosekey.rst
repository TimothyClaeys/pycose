COSE Key
=============


:mod:`pycose.keys.cosekey`
--------------------------

COSE Key objects hold cryptographic keys. They can be encoded as a CBOR map and can be
embedded in COSE Headers for transportation inside a COSE message.

.. autoclass:: pycose.keys.cosekey.KTY
    :members:
    :undoc-members:

.. autoclass:: pycose.keys.cosekey.KeyOps
    :members:
    :undoc-members:

.. autoclass:: pycose.keys.cosekey.EllipticCurveType
    :members:
    :undoc-members:


.. autoclass:: pycose.keys.cosekey.CoseKey(abstract class)
    :members:
    :undoc-members:
    :exclude-members: _KTY
