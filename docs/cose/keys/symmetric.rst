Symmetric Key
=============

To encode/encrypt/authenticate or decode/decrypt/verify the payload of COSE messages Enc0message, Mac0Message,
EncMessage, and/or MacMessage the COSE message object requires a COSE key of type :class:`~cose.keys.symmetric.SymmetricKey`.


Example usage COSE Symmetric Keys:

Example 1:
----------

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify
    >>> from cose.keys import SymmetricKey, CoseKey
    >>> from cose.algorithms import A128GCM
    >>> from cose.keys.keytype import KtySymmetric

    >>> # create key object from a dict
    >>> simple_dict = {
    ...     'KTY': KtySymmetric,
    ...     'ALG': A128GCM,
    ...     'K': unhexlify(b'000102030405060708090a0b0c0d0e0f')}

    >>> cose_key = CoseKey.from_dict(simple_dict)

    >>> #encode/serialize key
    >>> serialized_key = cose_key.encode()
    >>> serialized_key
    b'\xa4\x01\x04\x03\x01 P\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x04\x80'

    >>> CoseKey.decode(serialized_key)
    <COSE_Key(Symmetric): {'SymKpK': b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f', 'KpKty': 'KtySymmetric', 'KpAlg': 'A128GCM', 'KpKeyOps': []}>

Example 2:
----------

.. doctest::
    :pyversion: >= 3.6

    >>> from cose.keys import SymmetricKey

    >>> # generate a random key
    >>> cose_key = SymmetricKey.generate_key(key_len=16)

.. module:: cose.keys.symmetric

.. autoclass:: SymmetricKey
    :members:
    :inherited-members: alg, kty, kid, key_ops, base_iv
    :exclude-members: record_kty, clear, get, items, keys, pop, popitem, setdefault, update, values
