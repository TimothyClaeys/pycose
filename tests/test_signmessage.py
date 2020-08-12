from binascii import unhexlify

from pytest import fixture, mark, skip

from pycose import CoseMessage
from pycose.cosekey import EC2, KeyOps
from pycose.signmessage import SignMessage, CoseSignature
from tests.conftest import generic_test_setup, create_cose_key


@fixture
def setup_sign_tests(sign_test_input: dict) -> tuple:
    return generic_test_setup(sign_test_input)


@mark.encoding
def test_sign_encoding(setup_sign_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_sign_tests

    sign = SignMessage(
        phdr=test_input['sign'].get('protected', {}),
        uhdr=test_input['sign'].get('unprotected', {}),
        payload=test_input['plaintext'].encode('utf-8'),
    )

    signer_key = create_cose_key(EC2, test_input['sign']['signers'][0]['key'], KeyOps.SIGN)

    signer = test_input["sign"]['signers'][0]
    signer = CoseSignature(
        cose_sign_msg=sign,
        phdr=signer.get('protected'),
        uhdr=signer.get('unprotected'),
        external_aad=unhexlify(signer.get("external", b'')),
        key=signer_key
    )

    sign.signatures.append(signer)

    assert signer._sig_structure == unhexlify(test_intermediate['signers'][0]["ToBeSign_hex"])

    # verify encoding (with automatic tag computation)
    if fail:
        assert sign.encode() != unhexlify(test_output)
    else:
        assert sign.encode() == unhexlify(test_output)


@mark.decoding
def test_sign_encoding(setup_sign_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_sign_tests

    if fail:
        skip("invalid test input")

    cose_msg = CoseMessage.decode(unhexlify(test_output))

    assert cose_msg.phdr == test_input['sign'].get('protected', {})
    assert cose_msg.uhdr == test_input['sign'].get('unprotected', {})
    assert cose_msg.payload == test_input.get('plaintext', "").encode('utf-8')

    assert len(cose_msg.signatures) == 1
    assert cose_msg.signatures[0].phdr == test_input['sign']['signers'][0].get('protected', {})
    assert cose_msg.signatures[0].uhdr == test_input['sign']['signers'][0].get('unprotected', {})

    # set up potential external data and keys
    cose_msg.signatures[0].external_aad = unhexlify(test_input['sign']['signers'][0].get('external', b''))
    cose_msg.signatures[0].key = create_cose_key(EC2, test_input['sign']['signers'][0]['key'], KeyOps.SIGN)

    assert cose_msg.signatures[0]._sig_structure == unhexlify(test_intermediate['signers'][0]["ToBeSign_hex"])
    assert cose_msg.signatures[0].verify_signature()


