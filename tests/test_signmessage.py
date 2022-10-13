from binascii import hexlify, unhexlify

import cbor2
import pytest

from pycose.messages.cosemessage import CoseMessage
from pycose.messages.signmessage import SignMessage
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
        assert hexlify(s._sig_structure) == hexlify(s_output['structure'])
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


@pytest.mark.xfail(reason="Message not tagged", raises=AttributeError)
def test_sign1_decoding(test_sign):
    test_input = test_sign['input']
    test_output = test_sign['output']

    msg = CoseMessage.decode(cbor2.dumps(test_output['result']))

    for s, s_input, s_output in zip(msg.signers, test_input['signers'], test_output['signers']):
        s.external_aad = unhexlify(s_input['external_aad'])
        s.key = s_input['signing_key']
        assert hexlify(s._sig_structure) == hexlify(s_output['structure'])
        assert s.verify_signature()
