Examples
========

This page provides some examples on how to use the API to create different types of ``cose`` messages.

COSE Encrypt0
-------------

The example creates a COSE Encrypt0 message. The message is encrypted with AES-GCM with a 128-bit key.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify, hexlify

    >>> from cose.messages import Enc0Message, CoseMessage
    >>> from cose.keys import CoseKey
    >>> from cose.algorithms import A128GCM
    >>> from cose.headers import Algorithm, KID, IV
    >>> from cose.keys.keyparam import KpKty, SymKpK, KpKeyOps
    >>> from cose.keys.keytype import KtySymmetric
    >>> from cose.keys.keyops import EncryptOp, DecryptOp

    >>> msg = Enc0Message(
    ...     phdr = {Algorithm: A128GCM, IV: b'000102030405060708090a0b0c'},
    ...     uhdr = {KID: b'kid1'},
    ...     payload = 'some secret message'.encode('utf-8'))

    >>> msg
    <COSE_Encrypt0: [{'Algorithm': 'A128GCM', 'IV': "b'00010' ... (26 B)"}, {'KID': b'kid1'}, b'some ' ... (19 B)]>

    >>> cose_key = {
    ...     KpKty: KtySymmetric,
    ...     SymKpK: unhexlify(b'000102030405060708090a0b0c0d0e0f'),
    ...     KpKeyOps: [EncryptOp, DecryptOp]}

    >>> cose_key = CoseKey.from_dict(cose_key)
    >>> cose_key
    <COSE_Key(Symmetric): {'SymKpK': "b'\\x00\\x01\\x02\\x03\\x04' ... (16 B)", 'KpKty': 'KtySymmetric', 'KpKeyOps': ['EncryptOp', 'DecryptOp']}>

    >>> msg.key = cose_key
    >>> # the encode() function performs the encryption automatically
    >>> encoded = msg.encode()
    >>> hexlify(encoded)
    b'd0835820a2010105581a3030303130323033303430353036303730383039306130623063a104446b6964315823cca3441a2464d240e09fe9ee0ea42a7852a4f41d9945325c1f8d3b1353b8eb83e6a62f'

    >>> # decode and decrypt
    >>> decoded = CoseMessage.decode(encoded)
    >>> decoded
    <COSE_Encrypt0: [{'Algorithm': 'A128GCM', 'IV': "b'00010' ... (26 B)"}, {'KID': b'kid1'}, b'\xcc\xa3D\x1a$' ... (35 B)]>

    >>> decoded.key = cose_key
    >>> hexlify(decoded.payload)
    b'cca3441a2464d240e09fe9ee0ea42a7852a4f41d9945325c1f8d3b1353b8eb83e6a62f'

    >>> decoded.decrypt()
    b'some secret message'


COSE Sign1
----------

The example creates a COSE Sign1 message. The message is signed with EdDSA.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify, hexlify

    >>> from cose.messages import Sign1Message, CoseMessage
    >>> from cose.keys import CoseKey
    >>> from cose.headers import Algorithm, KID
    >>> from cose.algorithms import EdDSA
    >>> from cose.keys.curves import Ed25519
    >>> from cose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
    >>> from cose.keys.keytype import KtyOKP
    >>> from cose.keys.keyops import SignOp, VerifyOp

    >>> msg = Sign1Message(
    ...     phdr = {Algorithm: EdDSA, KID: b'kid2'},
    ...     payload = 'signed message'.encode('utf-8'))

    >>> msg
    <COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'' ... (0 B)]>


    >>> cose_key = {
    ...     KpKty: KtyOKP,
    ...     OKPKpCurve: Ed25519,
    ...     KpKeyOps: [SignOp, VerifyOp],
    ...     OKPKpD: unhexlify(b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
    ...     OKPKpX: unhexlify(b'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')}

    >>> cose_key = CoseKey.from_dict(cose_key)
    >>> cose_key
    <COSE_Key(OKPKey): {'OKPKpD': "b'\\x9da\\xb1\\x9d\\xef' ... (32 B)", 'OKPKpX': "b'\\xd7Z\\x98\\x01\\x82' ... (32 B)", 'OKPKpCurve': 'Ed25519', 'KpKty': 'KtyOKP', 'KpKeyOps': ['SignOp', 'VerifyOp']}>

    >>> msg.key = cose_key
    >>> # the encode() function performs the signing automatically
    >>> encoded = msg.encode()
    >>> hexlify(encoded)
    b'd28449a2012704446b696432a04e7369676e6564206d6573736167655840cc87665ffd3fa33d96f3b606fcedeaef839423221872d0bfa196e069a189a607c2284924c3abb80e942466cd300cc5d18fe4e5ea1f3ebdb62ef8419109447d03'

    >>> # decode and verify the signature
    >>> decoded = CoseMessage.decode(encoded)
    >>> decoded
    <COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'\xcc\x87f_\xfd' ... (64 B)]>

    >>> decoded.key = cose_key
    >>> decoded.verify_signature()
    True

    >>> decoded.payload
    b'signed message'


COSE MAC0
---------

The example creates a COSE Mac0 message. The message is authenticated with HMAC-256.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify, hexlify

    >>> from cose.messages import Mac0Message, CoseMessage
    >>> from cose.keys import CoseKey
    >>> from cose.algorithms import HMAC256
    >>> from cose.headers import Algorithm, KID
    >>> from cose.keys.keyparam import KpKty, SymKpK, KpKeyOps
    >>> from cose.keys.keytype import KtySymmetric
    >>> from cose.keys.keyops import MacCreateOp, MacVerifyOp

    >>> msg = Mac0Message(
    ...     phdr = {Algorithm: HMAC256},
    ...     uhdr = {KID: b'kid3'},
    ...     payload ='authenticated message'.encode('utf-8'))

    >>> msg
    <COSE_Mac0: [{'Algorithm': 'HMAC256'}, {'KID': b'kid3'}, b'authe' ... (21 B), b'' ... (0 B)]>

    >>> cose_key = {
    ...     KpKty: KtySymmetric,
    ...     SymKpK: unhexlify(b'000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f'),
    ...     KpKeyOps: [MacCreateOp, MacVerifyOp]}

    >>> cose_key = CoseKey.from_dict(cose_key)
    >>> cose_key
    <COSE_Key(Symmetric): {'SymKpK': "b'\\x00\\x01\\x02\\x03\\x04' ... (32 B)", 'KpKty': 'KtySymmetric', 'KpKeyOps': ['MacCreateOp', 'MacVerifyOp']}>

    >>> msg.key = cose_key
    >>> # the encode() function automatically computes the authentication tag
    >>> encoded = msg.encode()
    >>> hexlify(encoded)
    b'd18443a10105a104446b6964335561757468656e74696361746564206d657373616765582019f6c7d8ddfeaceea6ba4f1cafb563cbf3be157653e29f3258b2957cf23f4e17'

    >>> # decode and authenticate tag
    >>> decoded = CoseMessage.decode(encoded)
    >>> decoded
    <COSE_Mac0: [{'Algorithm': 'HMAC256'}, {'KID': b'kid3'}, b'authe' ... (21 B), b'\x19\xf6\xc7\xd8\xdd' ... (32 B)]>

    >>> decoded.key = cose_key
    >>> hexlify(decoded.payload)
    b'61757468656e74696361746564206d657373616765'

    >>> hexlify(decoded.auth_tag)
    b'19f6c7d8ddfeaceea6ba4f1cafb563cbf3be157653e29f3258b2957cf23f4e17'

    >>> decoded.verify_tag()
    True

COSE Encrypt
------------

The example creates a COSE Encrypt message. The message carries a single recipient which derives the CEK using the
direct key agreement method. The sender is using an ephemeral key.

.. doctest::
    :pyversion: >= 3.6

    >>> from binascii import unhexlify, hexlify
    >>> from copy import deepcopy

    >>> from cose.messages import EncMessage, CoseMessage
    >>> from cose.keys import CoseKey
    >>> from cose.messages.recipient import DirectKeyAgreement
    >>> from cose.headers import Algorithm, KID, StaticKey, EphemeralKey, IV
    >>> from cose.algorithms import EcdhEsHKDF256, A128GCM
    >>> from cose.keys.keyparam import KpKty, EC2KpD, EC2KpX, KpKeyOps, EC2KpCurve, EC2KpY, KpKid
    >>> from cose.keys.keytype import KtyEC2
    >>> from cose.keys.curves import P256
    >>> from cose.keys.keyops import DeriveKeyOp

    >>> # ephemeral sender key is generated
    >>> ephemeral_sender_key = {
    ...     KpKty: KtyEC2,
    ...     KpKid: b"peregrin.took@tuckborough.example",
    ...     KpKeyOps: [DeriveKeyOp],
    ...     EC2KpCurve: P256,
    ...     EC2KpX: unhexlify(b'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280'),
    ...     EC2KpY: unhexlify(b'f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb'),
    ...     EC2KpD: unhexlify(b'02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3')}
    >>> ephemeral_sender_key = CoseKey.from_dict(ephemeral_sender_key)
    >>> ephemeral_sender_key
    <COSE_Key(EC2Key): {'EC2KpD': "b'\\x02\\xd1\\xf7\\xe6\\xf2' ... (32 B)", 'EC2KpY': "b'\\xf0\\x14\\x00\\xb0\\x89' ... (32 B)", 'EC2KpX': "b'\\x98\\xf5\\nO\\xf6' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpKid': b'peregrin.took@tuckborough.example', 'KpKeyOps': ['DeriveKeyOp']}>

    >>> # static receiver key must be obtained in an out-of-bounds way
    >>> # (public key of the receiver, necessary for an ECDH computation)
    >>> static_receiver_key = {
    ...     KpKty: KtyEC2,
    ...     KpKid: b"meriadoc.brandybuck@buckland.example",
    ...     KpKeyOps: [DeriveKeyOp],
    ...     EC2KpCurve: P256,
    ...     EC2KpX: unhexlify(b'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d'),
    ...     EC2KpY: unhexlify(b'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c')}
    >>> static_receiver_key = CoseKey.from_dict(static_receiver_key)
    >>> static_receiver_key
    <COSE_Key(EC2Key): {'EC2KpY': "b'\\x1eR\\xedup' ... (32 B)", 'EC2KpX': "b'e\\xed\\xa5\\xa1%' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpKid': b'meriadoc.brandybuck@buckland.example', 'KpKeyOps': ['DeriveKeyOp']}>

    >>> # Make a copy from the ephemeral key and make sure the public part is added to the header of recipient.
    >>> # Otherwise the receiving side cannot derive the CEK, using the ECDH computation.
    >>> ephemeral_public = deepcopy(ephemeral_sender_key)

    >>> # remove redundant and secret information
    >>> del ephemeral_public[KpKeyOps]
    >>> del ephemeral_public[EC2KpD]
    >>> ephemeral_public
    <COSE_Key(EC2Key): {'EC2KpY': "b'\\xf0\\x14\\x00\\xb0\\x89' ... (32 B)", 'EC2KpX': "b'\\x98\\xf5\\nO\\xf6' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpKid': b'peregrin.took@tuckborough.example'}>

    >>> recipient = DirectKeyAgreement(
    ...     phdr = {Algorithm: EcdhEsHKDF256},
    ...     uhdr = {EphemeralKey: ephemeral_public})

    >>> # provide the recipient object with its ephemeral key and the static receiver key
    >>> recipient.key = ephemeral_sender_key
    >>> recipient.local_attrs = {StaticKey: static_receiver_key}

    >>> msg = EncMessage(
    ...     phdr = {Algorithm: A128GCM},
    ...     uhdr = {IV: unhexlify(b'C9CF4DF2FE6C632BF7886413')},
    ...     payload = 'This is the content'.encode('utf-8'),
    ...     recipients = [recipient])
    >>> msg
    <COSE_Encrypt: [{'Algorithm': 'A128GCM'}, {'IV': "b'\\xc9\\xcfM\\xf2\\xfe' ... (12 B)"}, b'This ' ... (19 B), [<COSE_Recipient: [{'Algorithm': 'EcdhEsHKDF256'}, {'EphemeralKey': <COSE_Key(EC2Key): {'EC2KpY': "b'\\xf0\\x14\\x00\\xb0\\x89' ... (32 B)", 'EC2KpX': "b'\\x98\\xf5\\nO\\xf6' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpKid': b'peregrin.took@tuckborough.example'}>}, b'' ... (0 B), []]>]]>

    >>> encoded = msg.encode()
    >>> hexlify(encoded)
    b'd8608443a10101a1054cc9cf4df2fe6c632bf788641358237adbe2709ca818fb415f1e5df66f4e1a51053b791f61288b65d131fa62bf37731aba62818344a1013818a120a50102025821706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c65200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280225820f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb40'

    >>> # decode and decrypt
    >>> decoded = CoseMessage.decode(encoded)
    >>> decoded
    <COSE_Encrypt: [{'Algorithm': 'A128GCM'}, {'IV': "b'\\xc9\\xcfM\\xf2\\xfe' ... (12 B)"}, b'z\xdb\xe2p\x9c' ... (35 B), [<COSE_Recipient: [{'Algorithm': 'EcdhEsHKDF256'}, {'EphemeralKey': <COSE_Key(EC2Key): {'EC2KpY': "b'\\xf0\\x14\\x00\\xb0\\x89' ... (32 B)", 'EC2KpX': "b'\\x98\\xf5\\nO\\xf6' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpKid': b'peregrin.took@tuckborough.example'}>}, b'' ... (0 B), []]>]]>

    >>> decoded.recipients
    [<COSE_Recipient: [{'Algorithm': 'EcdhEsHKDF256'}, {'EphemeralKey': <COSE_Key(EC2Key): {'EC2KpY': "b'\\xf0\\x14\\x00\\xb0\\x89' ... (32 B)", 'EC2KpX': "b'\\x98\\xf5\\nO\\xf6' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpKid': b'peregrin.took@tuckborough.example'}>}, b'' ... (0 B), []]>]

    >>> # set up static receiver key (this time with the private part included)
    >>> static_receiver_key = {
    ...     KpKty: KtyEC2,
    ...     KpKid: b"meriadoc.brandybuck@buckland.example",
    ...     KpKeyOps: [DeriveKeyOp],
    ...     EC2KpCurve: P256,
    ...     EC2KpX: unhexlify(b'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d'),
    ...     EC2KpY: unhexlify(b'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c'),
    ...     EC2KpD: unhexlify(b'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf')}
    >>> static_receiver_key = CoseKey.from_dict(static_receiver_key)

    >>> decoded.recipients[0].key = static_receiver_key
    >>> decoded.decrypt(decoded.recipients[0])
    b'This is the content'
