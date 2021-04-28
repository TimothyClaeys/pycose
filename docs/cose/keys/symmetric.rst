Symmetric Key
=============

Overview
--------

To encode/encrypt/authenticate or decode/decrypt/verify the payload of COSE messages
:class:`~cose.messages.enc0message.Enc0Message` , :class:`~cose.messages.mac0message.Mac0Message`,
:class:`~cose.messages.encmessage.EncMessage`, and :class:`~cose.messages.macmessage.Mac0Message`
the COSE message object requires a COSE key of type :class:`~cose.keys.symmetric.SymmetricKey`.

COSE Symmetric keys can be created using the :class:`~cose.keys.symmetric.SymmetricKey` class or from a standard Python
dictionary. The following two examples shows how to create COSE Symmetric keys using both methods. The keys are
serialized and subsequently deserialized.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import SymmetricKey, CoseKey

    >>> cose_key = SymmetricKey(k=unhexlify(b'000102030405060708090a0b0c0d0e0f'), optional_params={'ALG': 'A128GCM'})

    >>> #encode/serialize key
    >>> serialized_key = cose_key.encode()
    >>> serialized_key
    b'\xa3\x01\x04\x03\x01 P\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'

    >>> # deserialize key
    >>> CoseKey.decode(serialized_key)
    <COSE_Key(Symmetric): {'SymKpK': "b'\\x00\\x01\\x02\\x03\\x04' ... (16 B)", 'KpKty': 'KtySymmetric', 'KpAlg': 'A128GCM'}>


.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import SymmetricKey, CoseKey

    >>> # create key object from a dict, both the key type and key bytes (KTY and K) are mandatory attributes.
    >>> key_attribute_dict = {
    ...     'KTY': 'SYMMETRIC',
    ...     'ALG': 'A128GCM',
    ...     'K': unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    >>> cose_key = CoseKey.from_dict(key_attribute_dict)

    >>> #encode/serialize key
    >>> serialized_key = cose_key.encode()
    >>> serialized_key
    b'\xa3\x01\x04\x03\x01 P\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'

    >>> # deserialize key
    >>> CoseKey.decode(serialized_key)
    <COSE_Key(Symmetric): {'SymKpK': "b'\\x00\\x01\\x02\\x03\\x04' ... (16 B)", 'KpKty': 'KtySymmetric', 'KpAlg': 'A128GCM'}>

Alternatively you can use the :meth:`~cose.keys.symmetric.SymmetricKey.generate_key` method. It generates a random
COSE Symmetric Key with a given key length. Valid key lengths are 16, 24 and 32.

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.keys import SymmetricKey

    >>> # generate a random key
    >>> cose_key = SymmetricKey.generate_key(key_len=16)

When creating a COSE Symmetric Key from a dictionary, you have to make sure that the dictionary holds the
:class:`~cose.keys.keyparam.KpKty` and :class:`~cose.keys.keyparam.SymKpK` key attributes. These attributes are mandatory
for a valid COSE Symmetric Key. If you don't specify them, the :meth:`~cose.keys.cosekey.CoseKey.from_dict` will throw an
exception.

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.keys import SymmetricKey, CoseKey

    >>> key_attribute_dict = {
    ...     'ALG': 'A128GCM',
    ...     'K': unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    >>> cose_key = CoseKey.from_dict(key_attribute_dict)
    Traceback (most recent call last):
      File "/usr/lib/python3.6/doctest.py", line 1330, in __run
        compileflags, 1), test.globs)
      File "<doctest default[2]>", line 1, in <module>
        cose_key = CoseKey.from_dict(key_attribute_dict)
      File "/home/timothy/Projects/pycose/cose/keys/cosekey.py", line 69, in from_dict
        raise CoseIllegalKeyType("Could not decode CoseKey type, KpKty not set or unknown.")
    cose.exceptions.CoseIllegalKeyType: Could not decode CoseKey type, KpKty not set or unknown.

The key attributes of the COSE Symmetric Key can be represented by their string label, the integer identifier or the
corresponding python class.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import SymmetricKey, CoseKey
    >>> from cose.keys.keytype import KtySymmetric
    >>> from cose.algorithms import A128GCM
    >>> from cose.keys.keyparam import KpKty, KpAlg, SymKpK

    >>> # key attribute dict using string representations
    >>> key_attribute_dict1 = {
    ...     'KTY': 'SYMMETRIC',
    ...     'ALG': 'A128GCM',
    ...     'K': unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    >>> cose_key1 = CoseKey.from_dict(key_attribute_dict1)

    >>> # key attribute dict using integer identifiers
    >>> key_attribute_dict2 = {
    ...     1: 4,
    ...     3: 1,
    ...     -1: unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    >>> cose_key2 = CoseKey.from_dict(key_attribute_dict2)

    >>> # key attribute dict using Python classes
    >>> key_attribute_dict3 = {
    ...     KpKty: KtySymmetric,
    ...     KpAlg: A128GCM,
    ...     SymKpK: unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    >>> cose_key3 = CoseKey.from_dict(key_attribute_dict3)

    >>> # key attribute dict using a mix of attribute representations
    >>> key_attribute_dict4 = {
    ...     1: 'SYMMETRIC',
    ...     'ALG': A128GCM,
    ...     SymKpK: unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    >>> cose_key4 = CoseKey.from_dict(key_attribute_dict4)

    >>> # all COSE Symmetric key objects are equal
    >>> cose_key1 == cose_key2 == cose_key3 == cose_key4
    True


API
---

.. module:: cose.keys.symmetric

.. autoclass:: SymmetricKey
    :members:
    :inherited-members: alg, kty, kid, key_ops, base_iv
    :exclude-members: record_kty, clear, get, items, keys, pop, popitem, setdefault, update, values, verify
