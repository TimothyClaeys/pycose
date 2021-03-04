Encrypt0
========

:class:`~cose.messages.enc0message.Enc0Message` messages are used when there is a single receiver. The sender assumes that the receiver knows how
to find/derive the CEK to decrypt the payload. In case there are multiple receivers (each using a different key) or the
receiver requires more information to find/derive the CEK a :class:`~cose.messages.encmessage.EncMessage` should be used.

.. image:: ../../../images/encrypt0.png
    :width: 500px
    :align: center

.. doctest::

    >>> from cose import SymmetricKey, Enc0Message, CoseAlgorithms, KeyOps, CoseHeaderKeys

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce,,
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce,,
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce,,
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce,,
        b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

            # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
            >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

            # create a COSE_encrypt0 message
            >>> payload = b"Secret Message."
            >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
            >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

            # encode and wrap_cek the COSE message
            >>> msg = msg.encode(nonce, key)

            # change the key operation and decode/decrypt the message
            >>> key.key_ops = KeyOps.DECRYPT
            >>> msg = Enc0Message.from_dict(msg)
            >>> msg.phdr[CoseHeaderKeys.ALG]
            <CoseAlgorithms.A128GCM: 1>

            >>> msg.decrypt(nonce, key)
            b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and from_dict/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.decode(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce,,
        b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and decode/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.from_dict(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

        # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
        >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

        # create a COSE_encrypt0 message
        >>> payload = b"Secret Message."
        >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
        >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

        # encode and wrap_cek the COSE message
        >>> msg = msg.encode(nonce, key)

        # change the key operation and decode/decrypt the message
        >>> key.key_ops = KeyOps.DECRYPT
        >>> msg = Enc0Message.from_dict(msg)
        >>> msg.phdr[CoseHeaderKeys.ALG]
        <CoseAlgorithms.A128GCM: 1>

        >>> msg.decrypt(nonce, key)
        b'Secret Message.'

    # create a SymmetricKey COSE key (key bytes are generated with os.urandom)
    >>> key = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)

    # create a COSE_encrypt0 message
    >>> payload = b"Secret Message."
    >>> nonce = b'\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03'
    >>> msg = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload)

    # encode and wrap_cek the COSE message
    >>> msg = msg.encode(nonce, key)

    # change the key operation and from_dict/decrypt the message
    >>> key.key_ops = KeyOps.DECRYPT
    >>> msg = Enc0Message.decode(msg)
    >>> msg.phdr[CoseHeaderKeys.ALG]
    <CoseAlgorithms.A128GCM: 1>

    >>> msg.decrypt(nonce, key)
    b'Secret Message.'


.. module:: cose.messages.enc0message

.. autoclass:: Enc0Message
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
