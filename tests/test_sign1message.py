import cbor2
import pytest

from cose.keys.cosekey import CoseKey
from cose.keys.keyops import SignOp, VerifyOp
from cose.messages.cosemessage import CoseMessage
from cose.messages.sign1message import Sign1Message


def test_sign1_encoding(test_sign1):
    test_input = test_sign1['input']
    test_output = test_sign1['output']

    msg = Sign1Message(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        external_aad=test_input['external_aad'])

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._sig_structure == test_output['structure']

    key = CoseKey.from_dict(test_sign1["cek"])
    key.key_ops = [SignOp, VerifyOp]
    msg.key = key

    assert msg.compute_signature() == test_output['signature']
    assert cbor2.loads(msg.encode(tag=test_sign1['cbor_tag'])) == test_output['result']


@pytest.mark.xfail(reason="Message not tagged", raises=AttributeError)
def test_sign1_decoding(test_sign1):
    test_input = test_sign1['input']
    test_output = test_sign1['output']

    msg = CoseMessage.decode(cbor2.dumps(test_output['result']))
    msg.external_aad = test_input['external_aad']

    key = CoseKey.from_dict(test_sign1["cek"])
    key.key_ops = [VerifyOp]
    msg.key = key

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    assert msg.verify_signature()
