from binascii import unhexlify

import pytest

from cose.algorithms import CoseAlgorithm, Direct, A128GCM, AESCCM1664128, HMAC256, Es256
from cose.exceptions import CoseException
from cose.headers import Algorithm, KID, IV
from cose.keys import SymmetricKey, EC2Key
from cose.keys.curves import P256
from cose.messages import Enc0Message, EncMessage, Mac0Message, MacMessage, SignMessage, Sign1Message, CoseMessage
from cose.messages.recipient import DirectEncryption, CoseRecipient
from cose.messages.signer import Signer, CoseSignature


def test_header():
    alg_1 = Algorithm
    alg_2 = Algorithm

    assert alg_1 == alg_2
    assert id(alg_1) == id(alg_2)
    assert Algorithm == alg_2
    assert int(Algorithm()) == alg_2.identifier
    assert Algorithm.identifier == alg_2.identifier
    assert alg_1.fullname == "ALG"


def test_algorithm():
    gcm_1 = A128GCM
    gcm_2 = A128GCM
    ccm = AESCCM1664128

    assert ccm.identifier > gcm_1.identifier
    assert gcm_2 == gcm_1


def test_parsing():
    alg = CoseAlgorithm.from_id(-6)
    assert alg == Direct

    attr = Algorithm
    assert Direct == attr.value_parser(-6)


def test_disallow_unknown_headeer_attribute_encoding_decoding():
    with pytest.raises(CoseException) as excinfo:
        _ = Enc0Message(phdr={Algorithm: AESCCM1664128, "Custom-Header-Attr1": 7879},
                        allow_unknown_attributes=False)

    assert "Unknown COSE attribute with value" in str(excinfo.value)

    with pytest.raises(CoseException) as excinfo:
        _ = Enc0Message(uhdr={Algorithm: AESCCM1664128, "Custom-Header-Attr1": 7879},
                        allow_unknown_attributes=False)

    assert "Unknown COSE attribute with value" in str(excinfo.value)


def test_allow_unknown_header_attribute_encoding_decoding():
    msg = Enc0Message(phdr={Algorithm: AESCCM1664128, "Custom-Header-Attr1": 7879},
                      uhdr={KID: 8, IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 879})
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = CoseMessage.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr

    msg = EncMessage(phdr={Algorithm: AESCCM1664128, "Custom-Header-Attr1": 7879},
                     uhdr={KID: 8, IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878},
                     recipients=[DirectEncryption(uhdr={Algorithm: Direct, "Custom-Header-Attr3": 9999})])
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr
    assert "Custom-Header-Attr3" in msg.recipients[0].uhdr

    msg = msg.encode()

    msg_decoded = CoseMessage.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr
    assert "Custom-Header-Attr3" in msg_decoded.recipients[0].uhdr

    msg = Mac0Message(phdr={Algorithm: HMAC256, "Custom-Header-Attr1": 7879},
                      uhdr={KID: 8, IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878})
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = CoseMessage.decode(msg)

    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr

    msg = MacMessage(phdr={Algorithm: HMAC256, "Custom-Header-Attr1": 7879},
                     uhdr={KID: 8, IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878},
                     recipients=[DirectEncryption(uhdr={Algorithm: Direct, "Custom-Header-Attr3": 9999})])
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr
    assert "Custom-Header-Attr3" in msg.recipients[0].uhdr

    msg = msg.encode()

    msg_decoded = CoseMessage.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr
    assert "Custom-Header-Attr3" in msg_decoded.recipients[0].uhdr

    msg = SignMessage(phdr={"Custom-Header-Attr1": 7879},
                      uhdr={KID: 8, IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878},
                      signers=[CoseSignature(phdr={Algorithm: Es256, "Custom-Header-Attr3": 9999},
                                             key=EC2Key.generate_key(crv=P256))])

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = CoseMessage.decode(msg)

    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr
    assert "Custom-Header-Attr3" in msg_decoded.signers[0].phdr

    msg = Sign1Message(phdr={Algorithm: Es256, "Custom-Header-Attr1": 7879},
                       uhdr={KID: 8, "Custom-Header-Attr2": 878})
    msg.key = EC2Key.generate_key(crv=P256)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = CoseMessage.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr
