from binascii import hexlify, unhexlify

import cbor2
import pytest

from pycose.keys import EC2Key
from pycose.messages.signmessage import SignMessage
from pycose.messages.signer import CoseSignature
from pycose.exceptions import CoseException
from tests.conftest import _setup_signers


def test_sign_encoding(test_sign):
    test_input = test_sign['input']
    test_output = test_sign['output']

    signers = _setup_signers(test_input['signers'])

    msg = SignMessage(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        signers=signers)

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    for s, s_output in zip(msg.signers, test_output['signers']):
        assert hexlify(s._create_sig_structure()) == hexlify(s_output['structure'])
        if 'signature' in s_output:
            assert s.compute_signature() == s_output['signature']

    # remove signature for probabilistic behavior
    do_tag = test_sign['cbor_tag']
    msg_dec = cbor2.loads(msg.encode(tag=do_tag))
    test_dec = test_output['result']
    if 'signature' not in s_output:
        msg = msg_dec.value if do_tag else msg_dec
        for signer in msg[3]:
            signer[2] = b''

        msg = test_dec.value if do_tag else test_dec
        for signer in msg[3]:
            signer[2] = b''
    assert msg_dec == test_dec


def test_sign_decoding(test_sign):
    if not test_sign['cbor_tag']:
        pytest.skip("Missing CBOR tag")

    test_input = test_sign['input']
    test_output = test_sign['output']

    msg = SignMessage.decode(cbor2.dumps(test_output['result']))

    for s, s_input, s_output in zip(msg.signers, test_input['signers'], test_output['signers']):
        s.external_aad = unhexlify(s_input['external_aad'])
        s.key = s_input['signing_key']
        assert hexlify(s._create_sig_structure()) == hexlify(s_output['structure'])
        assert s.verify_signature()


def test_detached_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    signer = CoseSignature(phdr={'ALG': 'ES256'})
    signer.key = ec2_key

    msg = SignMessage(phdr={}, signers=[signer])

    encoded = msg.encode(detached_payload=payload)

    msg = SignMessage.decode(encoded)
    
    assert msg.payload is None
    
    signer = msg.signers[0]
    signer.key = ec2_key

    assert signer.verify_signature(detached_payload=payload)


def test_fail_on_missing_payload_signing():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    signer = CoseSignature(phdr={'ALG': 'ES256'})
    signer.key = ec2_key

    msg = SignMessage(phdr={}, signers=[signer])

    with pytest.raises(CoseException, match="Missing payload"):
        msg.encode()


def test_fail_on_missing_payload_verification():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    signer = CoseSignature(phdr={'ALG': 'ES256'})
    signer.key = ec2_key

    msg = SignMessage(phdr={}, signers=[signer])

    encoded = msg.encode(detached_payload=payload)

    msg = SignMessage.decode(encoded)

    signer = msg.signers[0]
    signer.key = ec2_key

    with pytest.raises(CoseException, match="Missing payload"):
        signer.verify_signature()
