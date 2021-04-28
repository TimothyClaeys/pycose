OKP Key
=======

Overview
--------

COSE OKP keys can be used for signing and verifying :class:`cose.messages.sign1message.Sign1Message` and
:class:`cose.messages.signmessage.SignMessage` COSE messages, and also for key agreement in
:class:`~cose.messages.recipient.KeyAgreementWithKeyWrap` and :class:`~cose.messages.recipient.DirectKeyAgreement` COSE
recipient structures.

COSE OKP keys can be created using the :class:`~cose.keys.okp.OKPKey` class or from a standard Python
dictionary. The following two examples shows how to create COSE OKP keys using both methods. The keys are
serialized and subsequently deserialized.

.. doctest::
    :pyversion: >= 3.6

    >>> import os
    >>> from binascii import unhexlify
    >>> from cose.keys import OKPKey, CoseKey

    >>> # get 32 random bytes as private key
    >>> private_key = unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    >>> cose_key = OKPKey(crv='ED25519', d=private_key, optional_params={'ALG': 'EDDSA'})

    >>> #encode/serialize key
    >>> serialized_key = cose_key.encode()
    >>> serialized_key
    b"\xa4\x01\x01\x03' \x06#X \x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

    >>> # deserialize key
    >>> CoseKey.decode(serialized_key)
    <COSE_Key(OKPKey): {'OKPKpD': "b'\\x00\\x01\\x02\\x03\\x04' ... (32 B)", 'OKPKpCurve': 'Ed25519', 'KpKty': 'KtyOKP', 'KpAlg': 'EdDSA'}>


.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import OKPKey, CoseKey

    >>> # create key object from a dict, both the key type and key bytes (KTY and K) are mandatory attributes.
    >>> key_attribute_dict = {
    ...     'KTY': 'OKP',
    ...     'CURVE': 'ED25519',
    ...     'ALG': 'EDDSA',
    ...     'D': unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key = CoseKey.from_dict(key_attribute_dict)

    >>> #encode/serialize key
    >>> serialized_key = cose_key.encode()
    >>> serialized_key
    b"\xa4\x01\x01\x03' \x06#X \x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

    >>> # deserialize key
    >>> CoseKey.decode(serialized_key)
    <COSE_Key(OKPKey): {'OKPKpD': "b'\\x00\\x01\\x02\\x03\\x04' ... (32 B)", 'OKPKpCurve': 'Ed25519', 'KpKty': 'KtyOKP', 'KpAlg': 'EdDSA'}>

Alternatively you can use the :meth:`~cose.keys.okp.OKPKey.generate_key` method. It generates a random
COSE OKP Key for a given curve. Valid curves are :class:`~cose.curves.X22519`, :class:`~cose.curves.X448`,
:class:`~cose.curves.ED25519`, and :class:`~cose.curves.ED448`.

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.keys import OKPKey

    >>> # generate a random key
    >>> cose_key = OKPKey.generate_key(crv='ED25519')

When creating a COSE OKP Key from a dictionary, you have to make sure that the dictionary holds the
:class:`~cose.keys.keyparam.KpKty`, :class:`~cose.keys.keyparam.OKPKpCurve`, and either
:class:`~cose.keys.keyparam.OKPKpD` (for private COSE OKP keys) or :class:`~cose.keys.keyparam.OKPKpX` (for public COSE
OKP keys) key attributes. These attributes are mandatory for a valid COSE OKP Key. If you don't specify them,
the :meth:`~cose.keys.cosekey.CoseKey.from_dict` will throw an exception.

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.keys import OKPKey, CoseKey

    >>> key_attribute_dict = {
    ...     'KTY': 'OKP',
    ...     'CURVE': 'ED25519'}

    >>> cose_key = CoseKey.from_dict(key_attribute_dict)
    Traceback (most recent call last):
      File "/usr/lib/python3.6/doctest.py", line 1330, in __run
        compileflags, 1), test.globs)
      File "<doctest default[2]>", line 1, in <module>
        cose_key = CoseKey.from_dict(key_attribute_dict)
      File "/home/timothy/Projects/pycose/cose/keys/cosekey.py", line 69, in from_dict
        key_obj = cls._key_types[received[KpKty.fullname]].from_dict(received)
      File "/home/timothy/Projects/pycose/cose/keys/okp.py", line 57, in from_dict
        return cls(crv=curve, x=x, d=d, optional_params=cose_key)
      File "/home/timothy/Projects/pycose/cose/keys/okp.py", line 68, in __init__
        raise CoseInvalidKey("Either the public values or the private value must be specified")
    cose.exceptions.CoseInvalidKey: Either the public values or the private value must be specified

The key attributes of the COSE OKP Key can be represented by their string label, the integer identifier or the
corresponding python class.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import OKPKey, CoseKey
    >>> from cose.keys.keytype import KtyOKP
    >>> from cose.algorithms import EdDSA
    >>> from cose.curves import Ed25519
    >>> from cose.keys.keyparam import KpKty, KpAlg, OKPKpD, OKPKpCurve

    >>> # key attribute dict using string representations
    >>> key_attribute_dict1 = {
    ...     'KTY': 'OKP',
    ...     'CURVE': 'ED25519',
    ...     'ALG': 'EDDSA',
    ...     'D': unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key1 = CoseKey.from_dict(key_attribute_dict1)

    >>> # key attribute dict using integer identifiers
    >>> key_attribute_dict2 = {
    ...     1: 1,
    ...     -1: 6,
    ...     3: -8,
    ...     -4: unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key2 = CoseKey.from_dict(key_attribute_dict2)

    >>> # key attribute dict using Python classes
    >>> key_attribute_dict3 = {
    ...     KpKty: KtyOKP,
    ...     OKPKpCurve: Ed25519,
    ...     KpAlg: EdDSA,
    ...     OKPKpD: unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key3 = CoseKey.from_dict(key_attribute_dict3)

    >>> # key attribute dict using a mix of attribute representations
    >>> key_attribute_dict4 = {
    ...     1: 'OKP',
    ...     OKPKpCurve: 6,
    ...     'ALG': EdDSA,
    ...     OKPKpD: unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key4 = CoseKey.from_dict(key_attribute_dict4)

    >>> # all COSE Symmetric key objects are equal
    >>> cose_key1 == cose_key2 == cose_key3 == cose_key4
    True

API
---

.. module:: cose.keys.okp

.. autoclass:: OKPKey
    :members:
    :inherited-members: alg, kty, kid, key_ops, base_iv
    :exclude-members: record_kty, decode, clear,  get, items, keys, pop, popitem, setdefault, update, values, verify

