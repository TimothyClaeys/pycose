import cbor2

from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import MacCreateOp, MacVerifyOp
from pycose.messages.macmessage import MacMessage
from tests.conftest import _setup_direct_encryption_recipients


def test_mac_direct_encryption_encoding(test_mac_direct_encryption_files):
    test_input = test_mac_direct_encryption_files['input']
    test_output = test_mac_direct_encryption_files['output']

    recipients = _setup_direct_encryption_recipients(test_input['recipients'])

    msg = MacMessage(
        test_input['protected'],
        test_input['unprotected'],
        test_input['plaintext'],
        external_aad=test_input['external_aad'],
        recipients=recipients)

    key = CoseKey.from_dict(test_mac_direct_encryption_files["cek"])
    key.key_ops = [MacCreateOp]

    msg.key = key

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._mac_structure == test_output['structure']

    assert cbor2.loads(msg.encode()) == test_output['result']


def test_mac_direct_encryption_decoding(test_mac_direct_encryption_files):
    test_output = test_mac_direct_encryption_files['output']
    test_input = test_mac_direct_encryption_files['input']

    msg = MacMessage.decode(cbor2.dumps((test_output['result'])))
    msg.external_aad = test_input['external_aad']

    key = CoseKey.from_dict(test_mac_direct_encryption_files["cek"])
    key.key_ops = [MacVerifyOp]

    msg.key = key

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    for r in msg.recipients:
        assert msg.verify_tag(r)
