COSE Algorithms
===============

Overview
--------

All :class:`~pycose.algorithms.CoseAlgorithm` have a `fullname` and `identifier` attribute. Both attributes can be used in
COSE headers and COSE keys.

.. doctest::
    :pyversion: >= 3.6

    >>> from pycose.messages import Enc0Message
    >>> from pycose.algorithms import A128GCM

    >>> msg1 = Enc0Message(phdr={'ALG': A128GCM})
    >>> msg2 = Enc0Message(phdr={'ALG': 'A128GCM'})
    >>> msg3 = Enc0Message(phdr={'ALG': 1})

    >>> # encoded protected header
    >>> msg1.phdr_encoded
    b'\xa1\x01\x01'

    >>> msg1.phdr_encoded == msg2.phdr_encoded == msg3.phdr_encoded
    True

The full list with COSE algorithms and their identifiers can be found at the
`IANA registry <https://www.iana.org/assignments/cose/cose.xhtml>`_

API
---

.. module:: pycose.algorithms

.. autoclass:: Shake256

.. autoclass:: Sha512

.. autoclass:: Sha384

.. autoclass:: Es512
    :members: get_hash_func, get_curve

.. autoclass:: Es384
    :members: get_hash_func, get_curve

.. autoclass:: EcdhSsA256KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhSsA192KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhSsA128KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhEsA256KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhEsA192KW
    :members: get_hash_func, get_key_wrap_func, get_key_length

.. autoclass:: EcdhEsA128KW
    :members: get_hash_func, get_key_wrap_func, get_key_length
