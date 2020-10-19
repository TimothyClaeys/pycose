COSE Encrypt0
=============

:class:`~cose.messages.enc0message.Enc0Message` messages are used when there is a single receiver. The sender assumes that the receiver knows how
to find/derive the CEK to decrypt the payload. In case there are multiple receivers (each using a different key) or the
receiver requires more information to find/derive the CEK a :class:`~cose.messages.encmessage.EncMessage` should be used.

.. code-block:: pycon

    >>> import os
    >>> from cose import CoseHeaderKeys, CoseAlgorithms, Enc0Message, KeyOps, SymmetricKey

    >>> # generate a nonce and key bytes
    >>> sender_nonce = os.urandom(16)
    >>> key_bytes = os.urandom(16)

    >>> # setup COSE key for encryption
    >>> ekey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)
    >>> ekey
    <COSE_Key(Symmetric): {kty: <KTY.SYMMETRIC: 4>, alg: <CoseAlgorithms.A128GCM: 1>, key_ops: <KeyOps.ENCRYPT: 3>, k: b'J\x074B+\x83x\x90\xbe\x92\xc6\x1c\x9f%\x7f\x84'}>

    >>> # create a COSE Encrypt0 message
    >>> msg = Enc0Message(
                {CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM},
                {CoseHeaderKeys.IV: sender_nonce},
                b'Secret message')
    >>> msg
    <COSE_Encrypt0: [{<CoseHeaderKeys.ALG: 1>: <CoseAlgorithms.A128GCM: 1>}, {<CoseHeaderKeys.IV: 5>: b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'}, b'Secre' ... (14 bytes)]>
    >>> encoded_msg = msg.encode(key=ekey, nonce=sender_nonce)
    >>> encoded_msg
    b'\xd0\x83C\xa1\x01\x01\xa1\x05P,v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaaX\x1e\xca\xf5\x90\x93\xeb\x08\xf3\x7f\xadv\x18\xe5^^\xe5\x18\x9e\xdfw\xef\x0e\x94$\xa5al\xed^~\xf6'

    >>> # decode message
    >>> decoded_msg = Enc0Message.decode(encoded_msg)
    >>> decoded_msg
    <COSE_Encrypt0: [{<CoseHeaderKeys.ALG: 1>: <CoseAlgorithms.A128GCM: 1>}, {<CoseHeaderKeys.IV: 5>: b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'}, b'\xca\xf5\x90\x93\xeb' ... (30 bytes)]>

    >>> decoded_msg.phdr[CoseHeaderKeys.ALG]
    <CoseAlgorithms.A128GCM: 1>
    >>> decoded_msg.uhdr[CoseHeaderKeys.IV]
    b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'

    >>> # decrypt the payload
    >>> dkey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.DECRYPT)
    >>> decoded_msg.decrypt(key=dkey, nonce=decoded_msg.uhdr[CoseHeaderKeys.IV])
    b'Secret message'
    >>> import os
    >>> from cose import CoseHeaderKeys, CoseAlgorithms, Enc0Message, KeyOps, SymmetricKey

    >>> # generate a nonce and key bytes
    >>> sender_nonce = os.urandom(16)
    >>> key_bytes = os.urandom(16)

    >>> # setup COSE key for encryption
    >>> ekey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)
    >>> ekey
    <COSE_Key(Symmetric): {kty: <KTY.SYMMETRIC: 4>, alg: <CoseAlgorithms.A128GCM: 1>, key_ops: <KeyOps.ENCRYPT: 3>, k: b'J\x074B+\x83x\x90\xbe\x92\xc6\x1c\x9f%\x7f\x84'}>

    >>> # create a COSE Encrypt0 message
    >>> msg = Enc0Message(
                {CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM},
                {CoseHeaderKeys.IV: sender_nonce},
                b'Secret message')
    >>> msg
    <COSE_Encrypt0: [{<CoseHeaderKeys.ALG: 1>: <CoseAlgorithms.A128GCM: 1>}, {<CoseHeaderKeys.IV: 5>: b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'}, b'Secre' ... (14 bytes)]>
    >>> encoded_msg = msg.encode(key=ekey, nonce=sender_nonce)
    >>> encoded_msg
    b'\xd0\x83C\xa1\x01\x01\xa1\x05P,v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaaX\x1e\xca\xf5\x90\x93\xeb\x08\xf3\x7f\xadv\x18\xe5^^\xe5\x18\x9e\xdfw\xef\x0e\x94$\xa5al\xed^~\xf6'

    >>> # decode message
    >>> decoded_msg = Enc0Message.decode(encoded_msg)
    >>> decoded_msg
    <COSE_Encrypt0: [{<CoseHeaderKeys.ALG: 1>: <CoseAlgorithms.A128GCM: 1>}, {<CoseHeaderKeys.IV: 5>: b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'}, b'\xca\xf5\x90\x93\xeb' ... (30 bytes)]>

    >>> decoded_msg.phdr[CoseHeaderKeys.ALG]
    <CoseAlgorithms.A128GCM: 1>
    >>> decoded_msg.uhdr[CoseHeaderKeys.IV]
    b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'

    >>> # decrypt the payload
    >>> dkey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.DECRYPT)
    >>> decoded_msg.decrypt(key=dkey, nonce=decoded_msg.uhdr[CoseHeaderKeys.IV])
    b'Secret message'
    >>> import os
    >>> from cose import CoseHeaderKeys, CoseAlgorithms, Enc0Message, KeyOps, SymmetricKey

    >>> # generate a nonce and key bytes
    >>> sender_nonce = os.urandom(16)
    >>> key_bytes = os.urandom(16)

    >>> # setup COSE key for encryption
    >>> ekey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)
    >>> ekey
    <COSE_Key(Symmetric): {kty: <KTY.SYMMETRIC: 4>, alg: <CoseAlgorithms.A128GCM: 1>, key_ops: <KeyOps.ENCRYPT: 3>, k: b'J\x074B+\x83x\x90\xbe\x92\xc6\x1c\x9f%\x7f\x84'}>

    >>> # create a COSE Encrypt0 message
    >>> msg = Enc0Message(
                {CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM},
                {CoseHeaderKeys.IV: sender_nonce},
                b'Secret message')
    >>> msg
    <COSE_Encrypt0: [{<CoseHeaderKeys.ALG: 1>: <CoseAlgorithms.A128GCM: 1>}, {<CoseHeaderKeys.IV: 5>: b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'}, b'Secre' ... (14 bytes)]>
    >>> encoded_msg = msg.encode(key=ekey, nonce=sender_nonce)
    >>> encoded_msg
    b'\xd0\x83C\xa1\x01\x01\xa1\x05P,v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaaX\x1e\xca\xf5\x90\x93\xeb\x08\xf3\x7f\xadv\x18\xe5^^\xe5\x18\x9e\xdfw\xef\x0e\x94$\xa5al\xed^~\xf6'

    >>> # decode message
    >>> decoded_msg = Enc0Message.decode(encoded_msg)
    >>> decoded_msg
    <COSE_Encrypt0: [{<CoseHeaderKeys.ALG: 1>: <CoseAlgorithms.A128GCM: 1>}, {<CoseHeaderKeys.IV: 5>: b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'}, b'\xca\xf5\x90\x93\xeb' ... (30 bytes)]>

    >>> decoded_msg.phdr[CoseHeaderKeys.ALG]
    <CoseAlgorithms.A128GCM: 1>
    >>> decoded_msg.uhdr[CoseHeaderKeys.IV]
    b',v\x16TW&\xf9\x05\x02Q\x9fr-I\xe4\xaa'

    >>> # decrypt the payload
    >>> dkey = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A128GCM, key_ops=KeyOps.DECRYPT)
    >>> decoded_msg.decrypt(key=dkey, nonce=decoded_msg.uhdr[CoseHeaderKeys.IV])
    b'Secret message'


.. module:: cose.messages.enc0message

.. autoclass:: Enc0Message
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
