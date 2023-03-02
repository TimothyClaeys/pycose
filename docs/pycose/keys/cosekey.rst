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

Alternatively, :class:`~pycose.keys.cosekey.CoseKey` objects can be initialized from key objects of the `pyca/cryptography`_ package:

.. _`pyca/cryptography`:  https://cryptography.io/

.. doctest::
    :pyversion: >= 3.6

    >>> from pycose.keys import CoseKey
    >>> from cryptography.hazmat.primitives.serialization import load_pem_public_key

    >>> encoded_key = '-----BEGIN PUBLIC KEY-----\n' \
    ...               'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyIBhex88X7Yrh5Q4hbmsUYpcVWNj\n' \
    ...               'mx1oE7TPomgpZJcQeNC3bX++GPsIWewWEGGFJKwHtRyfrL61DTTym3Rp8A==\n' \
    ...               '-----END PUBLIC KEY-----\n'
    >>> key = load_pem_public_key(encoded_key.encode("ascii"))
    
    >>> cosekey = CoseKey.from_cryptography_key(key)
    >>> cosekey
    <COSE_Key(EC2Key): {'EC2KpY': "b'\\x10x\\xd0\\xb7m' ... (32 B)", 'EC2KpX': "b'\\xc8\\x80a{\\x1f' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2'}>


Overview
--------

API
---

.. module:: pycose.keys.cosekey

.. autoclass:: CoseKey
    :members:
    :undoc-members:
    :exclude-members: record_kty, from_dict, base64decode, base64encode, encode, clear, get, items, keys, pop, popitem, setdefault, update, values, verify
