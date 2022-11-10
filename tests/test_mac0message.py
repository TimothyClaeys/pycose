import cbor2
import pytest

from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import MacVerifyOp, MacCreateOp
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.mac0message import Mac0Message


def test_mac0_encoding(test_mac0):
    test_input = test_mac0['input']
    test_output = test_mac0['output']

    msg = Mac0Message(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        external_aad=test_input['external_aad'])

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._mac_structure == test_output['structure']

    key = CoseKey.from_dict(test_mac0["cek"])
    key.key_ops = [MacCreateOp, MacVerifyOp]
    msg.key = key

    assert msg.compute_tag() == test_output['tag']
    assert cbor2.loads(msg.encode(tag=test_mac0['cbor_tag'])) == test_output['result']


def test_encrypt0_decoding(test_mac0):
    if not test_mac0['cbor_tag']:
        pytest.skip("Missing CBOR tag")

    test_input = test_mac0['input']
    test_output = test_mac0['output']

    msg = Mac0Message.decode(cbor2.dumps(test_output['result']))
    msg.external_aad = test_input['external_aad']

    key = CoseKey.from_dict(test_mac0["cek"])
    key.key_ops = [MacVerifyOp]
    msg.key = key

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    assert msg.verify_tag()
