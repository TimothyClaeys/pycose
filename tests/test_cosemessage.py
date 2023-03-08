import pytest

from pycose.algorithms import Es256
from pycose.headers import Algorithm
from pycose.keys import EC2Key
from pycose.keys.curves import P256
from pycose.messages import CoseMessage, Enc0Message, Sign1Message

@pytest.fixture
def sign1_message():
    msg = Sign1Message(phdr={Algorithm: Es256}, payload=b"")
    msg.key = EC2Key.generate_key(crv=P256)
    return msg.encode()

def test_unknown_message_type(sign1_message):
    decoded_msg = CoseMessage.decode(sign1_message)
    assert isinstance(decoded_msg, Sign1Message)

def test_incorrect_message_type(sign1_message):
    with pytest.raises(TypeError, match="CBOR tag .* does not match the expected message type"):
        Enc0Message.decode(sign1_message)
