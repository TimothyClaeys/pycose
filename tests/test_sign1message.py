from binascii import unhexlify

from pytest import fixture, mark, skip

from pycose import CoseMessage
from pycose.cosekey import CoseKey, EC2
from pycose.sign1message import Sign1Message
from tests.conftest import generic_test_setup, create_cose_key


@fixture
def setup_sign1_tests(sign1_test_input: dict) -> tuple:
    return generic_test_setup(sign1_test_input)


@mark.encoding
def test_sign1_encoding(setup_sign1_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_sign1_tests

    sign1 = Sign1Message(
        phdr=test_input['sign0'].get('protected', {}),
        uhdr=test_input['sign0'].get('unprotected', {}),
        payload=test_input.get('plaintext', '').encode('utf-8'),
        external_aad=unhexlify(test_input['sign0'].get("external", b''))
    )

    assert sign1._sig_structure == unhexlify(test_intermediate["ToBeSign_hex"])
    key = create_cose_key(EC2, test_input['sign0']['key'])

    sign1.key = key

    # verify encoding (with automatic tag computation)
    if fail:
        assert sign1.encode() != unhexlify(test_output)
    else:
        assert sign1.encode() == unhexlify(test_output)


@mark.decoding
def test_sign1_decoding(setup_sign1_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_sign1_tests

    if fail:
        skip("invalid test input")

    cose_msg = CoseMessage.decode(unhexlify(test_output))

    assert cose_msg.phdr == test_input['sign0'].get('protected', {})
    assert cose_msg.uhdr == test_input['sign0'].get('unprotected', {})
    assert cose_msg.payload == test_input.get('plaintext', "").encode('utf-8')

    # set up potential external data
    cose_msg.external_aad = unhexlify(test_input['sign0'].get("external", b''))

    key = create_cose_key(EC2, test_input['sign0']['key'])

    cose_msg.key = key
    assert cose_msg.verify_signature()
