COSE Key
=============


.. module:: cose.keys.cosekey

COSE Key objects hold cryptographic keys. They can be encoded as a CBOR map and can be
embedded in COSE Headers for transportation inside a COSE message.

.. autoclass:: KTY
    :members:
    :undoc-members:

.. autoclass:: KeyOps
    :members:
    :undoc-members:

.. autoclass:: CoseKey(abstract class)
    :members:
    :undoc-members:
    :exclude-members: _KTY
