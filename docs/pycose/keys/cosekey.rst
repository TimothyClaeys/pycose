COSE Key
=============

COSE Key objects hold cryptographic keys. They are encoded as a CBOR map and can be
embedded in COSE Headers for transportation inside a COSE message.
The :class:`~pycose.keys.cosekey.CoseKey` class is the abstract base class for all COSE key types:

* The :class:`~pycose.keys.okp.OKPKey` type
* The :class:`~pycose.keys.ec2.EC2Key` type
* The :class:`~pycose.keys.symmetric.SymmetricKey` type

The :class:`~pycose.keys.cosekey.CoseKey` class can be used to decode serialized COSE keys.

.. doctest::
    :pyversion: >= 3.6

    >>> from pycose.keys import CoseKey
    >>> from binascii import unhexlify

    >>> encoded_key = 'a401012006215820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c2358208f781a09'\
    ...               '5372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35'

    >>> cosekey = CoseKey.decode(unhexlify(encoded_key))
    >>> cosekey
    <COSE_Key(OKPKey): {'OKPKpD': "b'\\x8fx\\x1a\\tS' ... (32 B)", 'OKPKpX': "b'\\x89\\x8f\\xf7\\x9a\\x02' ... (32 B)", 'OKPKpCurve': 'Ed25519', 'KpKty': 'KtyOKP'}>

    >>> type(cosekey)
    <class 'pycose.keys.okp.OKPKey'>

    # Check the curve type of this key
    >>> cosekey.crv
    <class 'pycose.keys.curves.Ed25519'>

    # Check the private bytes of this key
    >>> cosekey.d
    b'\x8fx\x1a\tSr\xf8[m\x9fa\t\xaeB&\x11sM}\xbf\xa0\x06\x9a-\xf2\x93[\xb2\xe0S\xbf5'

Overview
--------

API
---

.. module:: pycose.keys.cosekey

.. autoclass:: CoseKey
    :members:
    :undoc-members:
    :exclude-members: record_kty, from_dict, base64decode, base64encode, encode, clear, get, items, keys, pop, popitem, setdefault, update, values, verify
