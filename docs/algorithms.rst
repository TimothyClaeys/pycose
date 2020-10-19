COSE Algorithms
===============

.. module:: cose.algorithms

The full list with COSE algorithms and their identifiers can be found at the
`IANA registry <https://www.iana.org/assignments/cose/cose.xhtml>`_

.. function:: config(algorithm)

    Extract the COSE algorithm configuration object.

.. function:: list_ciphers

    Returns a list with all supported ciphers

.. class:: _AlgorithmConfig

    An algorithm configuration object.

.. class:: CoseAlgorithms

    An enumeration for all supported COSE algorithms. Used by
    :class:`~cose.keys.cosekey.CoseKey` to perform cryptographic operations.

    .. code-block:: pycon

            >>> from cose.algorithms import CoseAlgorithms
            >>> CoseAlgorithms.ES256
            <CoseAlgorithms.ES256: -7>
            >>> CoseAlgorithms.ES256.id
            -7
            >>> CoseAlgorithms.ES256 == -7
            True
            >>> CoseAlgorithms.ES256 == "ES256"
            True
            >>> config(CoseAlgorithms.ES256)
            _AlgorithmConfig(primitive=None, kdf=None, curve=NIST256p, tag_length=None, hash=SHA256)


            >>> from cose.algorithms import CoseAlgorithms
            >>> CoseAlgorithms.ES256
            <CoseAlgorithms.ES256: -7>
            >>> CoseAlgorithms.ES256.id
            -7
            >>> CoseAlgorithms.ES256 == -7
            True
            >>> CoseAlgorithms.ES256 == "ES256"
            True
            >>> config(CoseAlgorithms.ES256)
            _AlgorithmConfig(primitive=None, kdf=None, curve=NIST256p, tag_length=None, hash=SHA256)


        >>> from cose.algorithms import CoseAlgorithms
        >>> CoseAlgorithms.ES256
        <CoseAlgorithms.ES256: -7>
        >>> CoseAlgorithms.ES256.id
        -7
        >>> CoseAlgorithms.ES256 == -7
        True
        >>> CoseAlgorithms.ES256 == "ES256"
        True
        >>> config(CoseAlgorithms.ES256)
        _AlgorithmConfig(primitive=None, kdf=None, curve=NIST256p, tag_length=None, hash=SHA256)

    .. attribute:: ES512

        ECDSA with NIST P-521 and SHA-512

    .. attribute:: ES384

        ECDSA with NIST P-384 and SHA-384

    .. attribute:: ECDH_SS_A256KW

        Key derivation with HKDF-SHA-256 and ECDH using static private and public keys. The resulting key (KEK) encrypts
        the CEK with AES-256 Key Wrap.

    .. attribute:: ECDH_SS_A192KW

        Key derivation with HKDF-SHA-256 and ECDH using static private and public keys. The resulting key (KEK) encrypts
        the CEK with AES-192 Key Wrap.

    .. attribute:: ECDH_SS_A128KW

        Key derivation with HKDF-SHA-256 and ECDH using static private and public keys. The resulting key (KEK) encrypts
        the CEK with AES-128 Key Wrap.

    .. attribute:: ECDH_ES_A256KW

        Key derivation with HKDF-SHA-256 and ECDH using an ephemeral public key and static private key. The resulting
        key (KEK) encrypts the CEK with AES-256 Key Wrap.

    .. attribute:: ECDH_ES_A192KW

        Key derivation with HKDF-SHA-256 and ECDH using an ephemeral public key and static private key. The resulting
        key (KEK) encrypts the CEK with AES-192 Key Wrap.

    .. attribute:: ECDH_ES_A128KW

        Key derivation with HKDF-SHA-256 and ECDH using an ephemeral public key and static private key. The resulting
        key (KEK) encrypts the CEK with AES-128 Key Wrap.

    .. attribute:: ECDH_SS_HKDF_512

        Key derivation with HKDF-SHA-512 and ECDH using static private and public keys.