Glossary
========

.. glossary::
    :sorted:

    plaintext
        User-readable data you care about.

    ciphertext
        The encoded data, it's not user readable. Potential attackers are able
        to see this.

    encryption
        The process of converting plaintext to ciphertext.

    decryption
        The process of converting ciphertext to plaintext.

    key
        Secret data is encoded with a function using this key. Sometimes
        multiple keys are used. These **must** be kept secret, if a key is
        exposed to an attacker, any data encrypted with it will be exposed.

    CEK
        Content Encryption Key - the key used to wrap_cek the COSE payload field.

    COSE
        CBOR Object Signing and Encryption

    CBOR
        Concise Binary Object Representation.