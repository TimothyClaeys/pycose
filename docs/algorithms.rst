COSE Algorithms
===============

.. module:: pycose.algorithms

The full list with COSE algorithms and their identifiers can be found at the
`IANA registry <https://www.iana.org/assignments/cose/cose.xhtml>`_


.. class:: _AlgorithmConfig

    An algorithm configuration object.

.. class:: CoseAlgorithms

    An enumeration for all supported COSE algorithms. Used by
    :class:`~pycose.keys.cosekey.CoseKey` to perform cryptographic operations.

    .. code-block:: pycon

        >>> from pycose.algorithms import CoseAlgorithms
        >>> CoseAlgorithms.ES256
        <CoseAlgorithms.ES256: -7>
        >>> CoseAlgorithms.ES256.id
        -7
        >>> CoseAlgorithms.ES256.id == int(CoseAlgorithms.ES256)
        True
        >>> config(CoseAlgorithms.ES256)
        _AlgorithmConfig(primitive=None, kdf=None, curve=NIST256p, tag_length=None, hash=256)

    .. attribute:: ES512

        ECDSA with NIST P-521 and SHA-512

    .. attribute:: ES384

        ECDSA with NIST P-384 and SHA-384

    .. attribute:: ECDH_SS_A256KW

        KEK key derivation with ECDH and static public/private keys. The resulting ECDH secret is then
        put through HKDF with SHA-256. Finally the KEK is used with AES-256 key wrapping algorithm to protect the CEK.


.. function:: config(algorithm)

    Extract the COSE algorithm configuration object.
