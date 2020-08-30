COSE Encrypt0
=============

:class:`~pycose.enc0message.Enc0Message` messages are used when there is a single receiver. The sender assumes that the receiver knows how
to find/derive the CEK to decrypt the payload. In case there are multiple receivers (each using a different key) or the
receiver requires more information to find/derive the CEK a :class:`~pycose.encmessage.EncMessage` should be used.

.. code-block:: pycon

    >>> import os
    >>> from pycose.keys import KeyOps, SymmetricKey
    >>> from pycose import CoseHeaderKeys, CoseAlgorithms, Enc0Message

    >>> # generate a nonce and key bytes
    >>> sender_nonce = os.urandom(16)
    >>> key_bytes = os.urandom()

    >>> # setup COSE key for encryption
    >>> ekey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)
    >>> ekey
    <COSE_Key(Symmetric): {kty: 4, alg: A128GCM, key_ops: 3, k: b'\x0ev\xa9^\xd5W\xb4\xb7\xf2\xaf\x8b\xde7\x94\x86\xbf'}>

    >>> # create a COSE Encrypt0 message
    >>> msg = Enc0Message(
                {CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM},
                {CoseHeaderKeys.IV: sender_nonce},
                b'Secret message')
    >>> msg
    <COSE_Encrypt0: [{<CoseHeaderKeys.ALG: 1>: 1}, {<CoseHeaderKeys.IV: 5>: b"\xaad\xb2UC\xc2?!\xd4k\x0bg'\x04\x00\xf8"}, b'Secre' ... (14 bytes)]>
    >>> encoded_msg = msg.encode(key=encryption_key, nonce=sender_nonce)
    >>> encoded_msg
    b"\xd0\x83C\xa1\x01\x01\xa1\x05P\xaad\xb2UC\xc2?!\xd4k\x0bg'\x04\x00\xf8X\x1eU\x12c\xd0X{\xc7b}*!\x85.]\x9d\\q\xc4\xcfRT\xdf{\xbe\x05\xb90\xf4\x9d\x90"

    >>> # decode message
    >>> decoded_msg = Enc0Message.decode(encoded_msg)
    >>> decoded_msg
    <COSE_Encrypt0: [{1: 1}, {5: b"\xaad\xb2UC\xc2?!\xd4k\x0bg'\x04\x00\xf8"}, b'U\x12c\xd0X' ... (30 bytes)]>
    >>> CoseAlgorithms(decoded_msg.phdr[CoseHeaderKeys.ALG])
    <CoseAlgorithms.A128GCM: 1>
    >>> decoded_msg.uhdr[CoseHeaderKeys.IV]
    b"\xaad\xb2UC\xc2?!\xd4k\x0bg'\x04\x00\xf8"

    >>> # decrypt the payload
    >>> dkey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.DECRYPT)
    >>> decoded_msg.decrypt(key=dkey, nonce=decoded_msg.uhdr[CoseHeaderKeys.IV])
    b'Secret message'


.. module:: pycose.enc0message

.. autoclass:: Enc0Message
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
