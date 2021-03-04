from binascii import unhexlify

import cbor2
import pytest

from cose.messages.cosemessage import CoseMessage
from cose.messages.signmessage import SignMessage
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
        assert s._sig_structure == s_output['structure']
        assert s.compute_signature() == s_output['signature']

    assert cbor2.loads(msg.encode(tag=test_sign['cbor_tag'])) == test_output['result']


@pytest.mark.xfail(reason="Message not tagged", raises=AttributeError)
def test_sign1_decoding(test_sign):
    test_input = test_sign['input']
    test_output = test_sign['output']

    msg = CoseMessage.decode(cbor2.dumps(test_output['result']))

    for s, s_input, s_output in zip(msg.signers, test_input['signers'], test_output['signers']):
        s.external_aad = unhexlify(s_input['external_aad'])
        s.key = s_input['signing_key']
        assert s._sig_structure == s_output['structure']
        assert s.verify_signature()
