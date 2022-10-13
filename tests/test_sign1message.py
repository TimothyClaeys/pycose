import cbor2
import pytest

from pycose.exceptions import CoseIllegalAlgorithm, CoseIllegalKeyOps
from pycose.keys import OKPKey, EC2Key
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.sign1message import Sign1Message


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


@pytest.mark.parametrize('alg', ['ES384', 'ES512'])
def test_fail_on_non_matching_algorithms_phdr(alg):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': alg})
    msg.key = ec2_key

    with pytest.raises(CoseIllegalAlgorithm) as excinfo:
        msg.encode()

    assert "Conflicting algorithms" in str(excinfo.value)


@pytest.mark.parametrize('ops',
                         ['VERIFY', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP',
                          'DERIVE_KEY', 'DERIVE_BITS', 'MAC_CREATE', 'MAC_VERIFY'])
def test_fail_on_illegal_keyops_signing(ops):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'KEY_OPS': [ops]})
    msg.key = ec2_key

    with pytest.raises(CoseIllegalKeyOps) as excinfo:
        msg.encode()

    assert "Illegal key operations specified." in str(excinfo.value)


@pytest.mark.parametrize('ops',
                         ['SIGN', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP',
                          'DERIVE_KEY', 'DERIVE_BITS', 'MAC_CREATE', 'MAC_VERIFY'])
def test_fail_on_illegal_keyops_verifying(ops):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256')
    msg.key = ec2_key

    msg = msg.encode()

    msg = CoseMessage.decode(msg)
    # set an illegal key op
    if ops in {'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP', 'MAC_CREATE', 'MAC_VERIFY'}:
        with pytest.raises(CoseIllegalKeyOps) as excinfo:
            ec2_key.key_ops = [ops]

        assert "Invalid COSE key operation" in str(excinfo.value)
        return
    else:
        ec2_key.key_ops = [ops]

    msg.key = ec2_key

    with pytest.raises(CoseIllegalKeyOps) as excinfo:
        msg.verify_signature()

    assert "Illegal key operations specified." in str(excinfo.value)
