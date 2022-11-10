import cbor2

from pycose.messages.enc0message import Enc0Message
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import EncryptOp, DecryptOp


def test_encrypt0_encoding(test_encrypt0):
    test_input = test_encrypt0['input']
    test_output = test_encrypt0['output']

    msg = Enc0Message(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        external_aad=test_input['external_aad'])

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._enc_structure == test_output['structure']

    key = CoseKey.from_dict(test_encrypt0["cek"])
    key.key_ops = [EncryptOp, DecryptOp]
    msg.key = key

    assert msg.encrypt() == test_output['ciphertext']
    assert cbor2.loads(msg.encode()) == test_output['result']


def test_encrypt0_decoding(test_encrypt0):
    test_input = test_encrypt0['input']
    test_output = test_encrypt0['output']

    msg = Enc0Message.decode(cbor2.dumps(test_output['result']))

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    key = CoseKey.from_dict(test_encrypt0["cek"])
    key.key_ops = [DecryptOp]
    msg.key = key

    assert msg.decrypt() == test_input['plaintext']


def test_encrypt0_round_trip(test_encrypt0):
    test_input = test_encrypt0['input']
    test_output = test_encrypt0['output']

    key = CoseKey.from_dict(test_encrypt0["cek"])
    key.key_ops = [DecryptOp, EncryptOp]

    msg = Enc0Message(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        external_aad=test_input['external_aad'],
        key=key)

    assert msg.encrypt() == test_output['ciphertext']
    assert cbor2.loads(msg.encode()) == test_output['result']

    msg = msg.encode()
    msg = Enc0Message.decode(msg)
    msg.key = key

    assert msg.decrypt() == test_input['plaintext']
