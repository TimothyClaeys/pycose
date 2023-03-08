from binascii import unhexlify
from os import urandom

import pytest

from pycose.algorithms import CoseAlgorithm, Direct, A128GCM, AESCCM1664128, HMAC256, Es256
from pycose.exceptions import CoseException
from pycose.headers import Algorithm, KID, IV, CoseHeaderAttribute, Critical, ContentType
from pycose.keys import SymmetricKey, EC2Key
from pycose.keys.curves import P256
from pycose.messages import Enc0Message, EncMessage, Mac0Message, MacMessage, SignMessage, Sign1Message
from pycose.messages.recipient import DirectEncryption
from pycose.messages.signer import CoseSignature


def test_cose_header_attribute_properties():
    """ Test the properties of COSE header attribute classes """

    alg_1 = Algorithm
    alg_2 = Algorithm

    assert alg_1 == alg_2
    assert id(alg_1) == id(alg_2)
    assert Algorithm == alg_2
    assert alg_1.identifier == alg_2.identifier
    assert Algorithm.identifier == alg_2.identifier
    assert alg_1.fullname == "ALG"

    kid_1 = KID
    kid_2 = KID

    assert kid_1 == kid_2
    assert id(kid_1) == id(kid_2)
    assert KID == kid_2
    assert kid_1.identifier == kid_2.identifier
    assert KID.identifier == kid_2.identifier
    assert kid_1.fullname == "KID"


def test_cose_algorithm_properties():
    """ Test the properties of the CoseAlgorithm classes """

    gcm_1 = A128GCM
    gcm_2 = A128GCM
    ccm = AESCCM1664128

    assert ccm.identifier > gcm_1.identifier
    assert gcm_2 == gcm_1


def test_cose_algorithm_id_parsing():
    """ Test the internal COSE algorithm identifier parsing function"""
    alg = CoseAlgorithm.from_id(-6)
    assert alg == Direct

    alg = CoseAlgorithm.from_id("DIRECT")
    assert alg == Direct

    alg = CoseAlgorithm.from_id(10)
    assert alg == AESCCM1664128

    alg = CoseAlgorithm.from_id("AES_CCM_16_64_128")
    assert alg == AESCCM1664128


def test_cose_header_attribute_id_parsing():
    """ Test the internal COSE header attribute identifier parsing function"""

    attr = CoseHeaderAttribute.from_id(1)
    assert Algorithm == attr

    attr = CoseHeaderAttribute.from_id('ALG')
    assert Algorithm == attr


def test_cose_header_attribute_value_parsing():
    """ Test the internal COSE header attribute value parsing function"""

    attr = Algorithm
    assert Direct == attr.value_parser(-6)

    attr = Algorithm
    assert Direct == attr.value_parser("DIRECT")


def test_cose_header_attribute_value_encoding():
    """
    Check the correct encoding of the COSE header attribute values:
        - algorithm attribute value as int/tstr
        - critical attribute value as array with one or more elements
        - content type attribute value as uint/tstr
        - kid attribute value as bstr
        - iv attribute value as bstr
    """

    # algorithm as int
    msg = Enc0Message(phdr={Algorithm: AESCCM1664128},
                      uhdr={IV: urandom(13)},
                      payload=b'this is the payload',
                      key=SymmetricKey.generate_key(16))

    msg = msg.encode()
    assert b"\xa1\x01\n" in msg

    decoded_msg = Enc0Message.decode(msg)
    assert decoded_msg.phdr[Algorithm] == AESCCM1664128

    # algorithm as tstr
    msg = Enc0Message(phdr={Algorithm: AESCCM1664128},
                      uhdr={IV: urandom(13)},
                      payload=b'this is the payload',
                      key=SymmetricKey.generate_key(16),
                      alg_tstr_encoding=True)

    msg = msg.encode()
    assert b"AES_CCM_16_64_128" in msg

    decoded_msg = Enc0Message.decode(msg)
    assert decoded_msg.phdr[Algorithm] == AESCCM1664128

    # critical
    msg = Enc0Message(phdr={Algorithm: AESCCM1664128, "A": 42, Critical: [1, "A"]},
                      uhdr={IV: urandom(13)},
                      payload=b'this is the payload',
                      key=SymmetricKey.generate_key(16))

    msg = msg.encode()
    assert b"\x82\x01\x61\x41" in msg

    decoded_msg = Enc0Message.decode(msg)
    assert decoded_msg.phdr[Critical] == [1, "A"]

    # content type as uint
    msg = Enc0Message(phdr={Algorithm: AESCCM1664128},
                      uhdr={IV: unhexlify(b'00000000000000000000000000'), ContentType: 60},
                      payload=b'this is the payload',
                      key=SymmetricKey.generate_key(16))

    msg = msg.encode()
    assert b"\x03\x18" in msg

    decoded_msg = Enc0Message.decode(msg)
    assert decoded_msg.uhdr[ContentType] == 60

    # content type as tstr
    msg = Enc0Message(phdr={Algorithm: AESCCM1664128},
                      uhdr={IV: unhexlify(b'00000000000000000000000000'), ContentType: "application/cbor"},
                      payload=b'this is the payload',
                      key=SymmetricKey.generate_key(16))

    msg = msg.encode()
    assert b"application/cbor" in msg

    decoded_msg = Enc0Message.decode(msg)
    assert decoded_msg.uhdr[ContentType] == "application/cbor"

    # kid as bstr
    msg = Enc0Message(phdr={Algorithm: AESCCM1664128},
                      uhdr={IV: unhexlify(b'00000000000000000000000000'), KID: b"foo"},
                      payload=b'this is the payload',
                      key=SymmetricKey.generate_key(16))

    msg = msg.encode()
    assert b"foo" in msg

    decoded_msg = Enc0Message.decode(msg)
    assert decoded_msg.uhdr[KID] == b"foo"


def test_disallow_unknown_header_attribute_encoding_decoding():
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
                      uhdr={KID: b'foo', IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 879})
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = Enc0Message.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr

    msg = EncMessage(phdr={Algorithm: AESCCM1664128, "Custom-Header-Attr1": 7879},
                     uhdr={KID: b'foo', IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878},
                     recipients=[DirectEncryption(uhdr={Algorithm: Direct, "Custom-Header-Attr3": 9999})])
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr
    assert "Custom-Header-Attr3" in msg.recipients[0].uhdr

    msg = msg.encode()

    msg_decoded = EncMessage.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr
    assert "Custom-Header-Attr3" in msg_decoded.recipients[0].uhdr

    msg = Mac0Message(phdr={Algorithm: HMAC256, "Custom-Header-Attr1": 7879},
                      uhdr={KID: b'foo', IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878})
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = Mac0Message.decode(msg)

    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr

    msg = MacMessage(phdr={Algorithm: HMAC256, "Custom-Header-Attr1": 7879},
                     uhdr={KID: b'foo', IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878},
                     recipients=[DirectEncryption(uhdr={Algorithm: Direct, "Custom-Header-Attr3": 9999})])
    msg.key = SymmetricKey.generate_key(key_len=16)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr
    assert "Custom-Header-Attr3" in msg.recipients[0].uhdr

    msg = msg.encode()

    msg_decoded = MacMessage.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr
    assert "Custom-Header-Attr3" in msg_decoded.recipients[0].uhdr

    msg = SignMessage(phdr={"Custom-Header-Attr1": 7879},
                      uhdr={KID: b'foo', IV: unhexlify(b'00000000000000000000000000'), "Custom-Header-Attr2": 878},
                      payload=b"",
                      signers=[CoseSignature(phdr={Algorithm: Es256, "Custom-Header-Attr3": 9999},
                                             key=EC2Key.generate_key(crv=P256))])

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = SignMessage.decode(msg)

    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr
    assert "Custom-Header-Attr3" in msg_decoded.signers[0].phdr

    msg = Sign1Message(phdr={Algorithm: Es256, "Custom-Header-Attr1": 7879},
                       uhdr={KID: b'foo', "Custom-Header-Attr2": 878},
                       payload=b"")
    msg.key = EC2Key.generate_key(crv=P256)

    assert "Custom-Header-Attr1" in msg.phdr
    assert "Custom-Header-Attr2" in msg.uhdr

    msg = msg.encode()

    msg_decoded = Sign1Message.decode(msg)
    assert "Custom-Header-Attr1" in msg_decoded.phdr
    assert "Custom-Header-Attr2" in msg_decoded.uhdr

def test_no_reencoding_of_protected_header():
    # The following protected header encodes {Alg: Es256, "foo": 1}, however,
    # it is crafted such that it would not be emitted by cbor2.
    # The integer 1 is encoded suboptimally using three bytes instead of one.
    # This is a test to ensure that the protected header is not re-encoded.
    phdr_encoded = unhexlify(b'A2012663666F6F190001')

    msg = Sign1Message(phdr_encoded=phdr_encoded, payload=b"")
    msg.key = EC2Key.generate_key(crv=P256)

    msg = msg.encode()
    msg_decoded = Sign1Message.decode(msg)
    
    assert msg_decoded.phdr_encoded == phdr_encoded
