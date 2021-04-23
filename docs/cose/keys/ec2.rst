EC2 Key
=======

Overview
--------

COSE EC2 keys can be used for signing and verifying :class:`cose.messages.sign1message.Sign1Message` and
:class:`cose.messages.signmessage.SignMessage` COSE messages, and also for key agreement in
:class:`~cose.messages.recipient.KeyAgreementWithKeyWrap` and :class:`~cose.messages.recipient.DirectKeyAgreement` COSE
recipient structures.

COSE EC2 keys can be created using the :class:`~cose.keys.ec2.EC2Key` class or from a standard Python
dictionary. The following two examples shows how to create COSE EC2 keys using both methods. The keys are
serialized and subsequently deserialized.

.. warning::
    The private keys in the following examples are not valid for the given curves. Since we are not using the COSE EC2
    Keys in the examples for signing, verifying or key agreement, this is not a problem. If you wish to create a COSE
    EC2 key with valid private and public values, you should use the :meth:`~cose.keys.ec2.EC2Key.generate_key` method.

.. doctest::
    :pyversion: >= 3.6

    >>> import os
    >>> from binascii import unhexlify
    >>> from cose.keys import EC2Key, CoseKey

    >>> # get 32 random bytes as private key (potentially not a valid key for curve P_256)
    >>> private_key = unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    >>> cose_key = EC2Key(crv='P_256', d=private_key, optional_params={'ALG': 'ES256'})

    >>> #encode/serialize key
    >>> serialized_key = cose_key.encode()
    >>> serialized_key
    b'\xa4\x01\x02\x03& \x01#X \x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'

    >>> # deserialize key
    >>> CoseKey.decode(serialized_key)
    <COSE_Key(EC2Key): {'EC2KpD': "b'\\x00\\x01\\x02\\x03\\x04' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpAlg': 'Es256'}>


.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import EC2Key, CoseKey

    >>> # create key object from a dict, both the key type and key bytes (KTY and K) are mandatory attributes.
    >>> key_attribute_dict = {
    ...     'KTY': 'EC2',
    ...     'CURVE': 'P_256',
    ...     'ALG': 'ES256',
    ...     'D': unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key = CoseKey.from_dict(key_attribute_dict)

    >>> #encode/serialize key
    >>> serialized_key = cose_key.encode()
    >>> serialized_key
    b'\xa4\x01\x02\x03& \x01#X \x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'

    >>> # deserialize key
    >>> CoseKey.decode(serialized_key)
    <COSE_Key(EC2Key): {'EC2KpD': "b'\\x00\\x01\\x02\\x03\\x04' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpAlg': 'Es256'}>

Alternatively you can use the :meth:`~cose.keys.ec2.EC2Key.generate_key` method. It generates a random
COSE EC2 Key for a given curve. Valid curves are :class:`~cose.curves.P256`, :class:`~cose.curves.P384`, and
:class:`~cose.curves.P521`.

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.keys import EC2Key

    >>> # generate a random key
    >>> cose_key = EC2Key.generate_key(crv='P_521')

When creating a COSE EC2 Key from a dictionary, you have to make sure that the dictionary holds the
:class:`~cose.keys.keyparam.KpKty`, :class:`~cose.keys.keyparam.EC2KpCurve`, and either
:class:`~cose.keys.keyparam.EC2KpD` (for private COSE EC2 keys) or :class:`~cose.keys.keyparam.EC2KpX` and
:class:`~cose.keys.keyparam.EC2KpY` (for public COSE EC2 keys) key attributes. These attributes are mandatory for a
valid COSE EC2 Key. If you don't specify them, the :meth:`~cose.keys.cosekey.CoseKey.from_dict` will throw an exception.

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.keys import EC2Key, CoseKey

    >>> key_attribute_dict = {
    ...     'KTY': 'EC2',
    ...     'CURVE': 'P_384'}

    >>> CoseKey.from_dict(key_attribute_dict)
    Traceback (most recent call last):
      File "/usr/lib/python3.6/doctest.py", line 1330, in __run
        compileflags, 1), test.globs)
      File "<doctest default[2]>", line 1, in <module>
        CoseKey.from_dict(key_attribute_dict)
      File "/home/timothy/Projects/pycose/cose/keys/cosekey.py", line 69, in from_dict
        key_obj = cls._key_types[received[KpKty.fullname]].from_dict(received)
      File "/home/timothy/Projects/pycose/cose/keys/ec2.py", line 63, in from_dict
        return cls(crv=curve, x=x, y=y, d=d, optional_params=cose_key)
      File "/home/timothy/Projects/pycose/cose/keys/ec2.py", line 74, in __init__
        raise CoseInvalidKey("Either the public values or the private value must be specified")
    cose.exceptions.CoseInvalidKey: Either the public values or the private value must be specified

The key attributes of the COSE EC2 Key can be represented by their string label, the integer identifier or the
corresponding python class.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import EC2Key, CoseKey
    >>> from cose.keys.keytype import KtyEC2
    >>> from cose.algorithms import Es256
    >>> from cose.curves import P256
    >>> from cose.keys.keyparam import KpKty, KpAlg, EC2KpD, EC2KpCurve

    >>> # key attribute dict using string representations
    >>> key_attribute_dict1 = {
    ...     'KTY': 'EC2',
    ...     'CURVE': 'P_256',
    ...     'ALG': 'ES256',
    ...     'D': unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key1 = CoseKey.from_dict(key_attribute_dict1)

    >>> # key attribute dict using integer identifiers
    >>> key_attribute_dict2 = {
    ...     1: 2,
    ...     -1: 1,
    ...     3: -7,
    ...     -4: unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key2 = CoseKey.from_dict(key_attribute_dict2)

    >>> # key attribute dict using Python classes
    >>> key_attribute_dict3 = {
    ...     KpKty: KtyEC2,
    ...     EC2KpCurve: P256,
    ...     KpAlg: Es256,
    ...     EC2KpD: unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key3 = CoseKey.from_dict(key_attribute_dict3)

    >>> # key attribute dict using a mix of attribute representations
    >>> key_attribute_dict4 = {
    ...     1: 'EC2',
    ...     EC2KpCurve: 1,
    ...     'ALG': Es256,
    ...     EC2KpD: unhexlify(b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')}

    >>> cose_key4 = CoseKey.from_dict(key_attribute_dict4)

    >>> # all COSE Symmetric key objects are equal
    >>> cose_key1 == cose_key2 == cose_key3 == cose_key4
    True

API
---

.. module:: cose.keys.ec2

.. autoclass:: EC2Key
    :members:
    :inherited-members: alg, kty, kid, key_ops, base_iv
    :exclude-members: record_kty, clear, decode, get, items, keys, pop, popitem, setdefault, update, values, verify
