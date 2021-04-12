COSE Key
=============

COSE Key objects hold cryptographic keys. They are encoded as a CBOR map and can be
embedded in COSE Headers for transportation inside a COSE message.

Overview
--------

API
---

.. module:: cose.keys.cosekey

.. autoclass:: CoseKey
    :members:
    :undoc-members:
    :exclude-members: record_kty, clear,  get, items, keys, pop, popitem, setdefault, update, values, verify
