from binascii import unhexlify

from pytest import fixture, mark

from pycose.cosekey import CoseKey, EC2
from pycose.sign1message import Sign1Message
from tests.conftest import generic_test_setup


@fixture
def setup_sign1_tests(sign1_test_input: dict) -> tuple:
    return generic_test_setup(sign1_test_input)


@mark.decoding
def test_sign1_encoding(setup_sign1_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_sign1_tests

    sign1 = Sign1Message(
        phdr=test_input['sign0'].get('protected', {}),
        uhdr=test_input['sign0'].get('unprotected', {}),
        payload=test_input.get('plaintext', '').encode('utf-8'),
        external_aad=unhexlify(test_input['sign0'].get("external", b''))
    )

    assert sign1._sig_structure == unhexlify(test_intermediate["ToBeSign_hex"])

    key = EC2(
        kid=test_input['sign0']["key"][CoseKey.Common.KID],
        x=CoseKey.base64decode(test_input["sign0"]["key"][EC2.EC2Prm.X]),
        y=CoseKey.base64decode(test_input["sign0"]["key"][EC2.EC2Prm.Y]),
        d=CoseKey.base64decode(test_input["sign0"]["key"][EC2.EC2Prm.D]),
    )

    sign1.key = key

    # verify encoding (with automatic tag computation)
    if fail:
        assert sign1.encode() != unhexlify(test_output)
    else:
        assert sign1.encode() == unhexlify(test_output)
