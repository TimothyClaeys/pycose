from binascii import unhexlify

from pytest import fixture, mark, skip

from cose import CoseMessage, OKP
from cose.keys.cosekey import KeyOps
from cose.keys.ec import EC2
from cose.messages.sign1message import Sign1Message
from tests.conftest import generic_test_setup, create_cose_key, extract_alg


@fixture
def setup_ec2sign1_tests(ec2_sign1_test_input: dict) -> tuple:
    return generic_test_setup(ec2_sign1_test_input)


@fixture
def setup_okpsign1_tests(okp_sign1_test_input: dict) -> tuple:
    return generic_test_setup(okp_sign1_test_input)


@mark.encoding
def test_ec2sign1_encoding(setup_ec2sign1_tests) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_ec2sign1_tests

    sign1 = Sign1Message(
        phdr=test_input['sign0'].get('protected', {}),
        uhdr=test_input['sign0'].get('unprotected', {}),
        payload=test_input.get('plaintext', '').encode('utf-8'),
        external_aad=unhexlify(test_input['sign0'].get("external", b'')))

    assert sign1._sig_structure == unhexlify(test_intermediate["ToBeSign_hex"])
    private_key = create_cose_key(EC2,
                                  test_input['sign0']['key'],
                                  usage=KeyOps.SIGN,
                                  alg=extract_alg(test_input["sign0"]))

    if fail:
        assert sign1.encode(private_key) != unhexlify(test_output)
    else:
        assert sign1.encode(private_key) == unhexlify(test_output)


@mark.decoding
def test_ec2sign1_decoding(setup_ec2sign1_tests) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_ec2sign1_tests

    if fail:
        skip("invalid test input")

    cose_msg: Sign1Message = CoseMessage.decode(unhexlify(test_output))

    assert cose_msg.phdr == test_input['sign0'].get('protected', {})
    assert cose_msg.uhdr == test_input['sign0'].get('unprotected', {})
    assert cose_msg.payload == test_input.get('plaintext', "").encode('utf-8')

    # set up potential external data
    cose_msg.external_aad = unhexlify(test_input['sign0'].get("external", b''))

    public_key = create_cose_key(EC2,
                                 test_input['sign0']['key'],
                                 usage=KeyOps.VERIFY,
                                 alg=extract_alg(test_input["sign0"]))

    assert cose_msg.verify_signature(public_key)


def test_okpsign1_encoding(setup_okpsign1_tests) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_okpsign1_tests

    sign1 = Sign1Message(
        phdr=test_input['sign0'].get('protected', {}),
        uhdr=test_input['sign0'].get('unprotected', {}),
        payload=test_input.get('plaintext', '').encode('utf-8'),
        external_aad=unhexlify(test_input['sign0'].get("external", b'')))

    assert sign1._sig_structure == unhexlify(test_intermediate["ToBeSign_hex"])

    private_key = create_cose_key(OKP,
                                  test_input['sign0']['key'],
                                  usage=KeyOps.SIGN,
                                  alg=extract_alg(test_input["sign0"]))

    if fail:
        assert sign1.encode(private_key) != unhexlify(test_output)
    else:
        assert sign1.encode(private_key) == unhexlify(test_output)


def test_okpsign1_decoding(setup_okpsign1_tests) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_okpsign1_tests

    if fail:
        skip("invalid test input")

    cose_msg: Sign1Message = CoseMessage.decode(unhexlify(test_output))

    # set up potential external data
    cose_msg.external_aad = unhexlify(test_input['sign0'].get("external", b''))

    public_key = create_cose_key(OKP,
                                 test_input['sign0']['key'],
                                 usage=KeyOps.VERIFY,
                                 alg=extract_alg(test_input["sign0"]))

    assert cose_msg.verify_signature(public_key)
