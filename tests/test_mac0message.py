from binascii import unhexlify

from pytest import skip, fixture, mark

from pycose import CoseMessage
from pycose.cosekey import SymmetricKey, CoseKey
from pycose.mac0message import Mac0Message
from tests.conftest import generic_test_setup


@fixture
def setup_mac0_tests(mac0_test_input: dict) -> tuple:
    return generic_test_setup(mac0_test_input)


@mark.decoding
def test_mac0_encoding(setup_mac0_tests: tuple) -> None:
    test_input, test_output, test_intermediate, fail = setup_mac0_tests

    mac0 = Mac0Message(
        phdr=test_input['mac0'].get('protected', {}),
        uhdr=test_input['mac0'].get('unprotected', {}),
        payload=test_input.get('plaintext', '').encode('utf-8'),
        external_aad=unhexlify(test_input['mac0'].get("external", b''))
    )

    assert mac0._mac_structure == unhexlify(test_intermediate["ToMac_hex"])

    key = SymmetricKey(
        k=CoseKey.base64decode(test_input["mac0"]["recipients"][0]["key"][SymmetricKey.SymPrm.K]),
        kid=test_input['mac0']['recipients'][0]["key"][CoseKey.Common.KID],
    )

    assert key.key_bytes == unhexlify(test_intermediate["CEK_hex"])

    mac0.key = key

    # verify encoding (with automatic tag computation)
    if fail:
        assert mac0.encode() != unhexlify(test_output)
    else:
        assert mac0.encode() == unhexlify(test_output)


def test_mac0_decoding(setup_mac0_tests: tuple) -> None:
    test_input, test_output, test_intermediate, fail = setup_mac0_tests

    if fail:
        skip("invalid test input")

    cose_msg = CoseMessage.decode(unhexlify(test_output))

    assert cose_msg.phdr == test_input['mac0'].get('protected', {})
    assert cose_msg.uhdr == test_input['mac0'].get('unprotected', {})
    assert cose_msg.payload == test_input.get('plaintext', "").encode('utf-8')

    # set up potential external data
    cose_msg.external_aad = unhexlify(test_input['mac0'].get("external", b''))

    key = SymmetricKey(
        k=CoseKey.base64decode(test_input["mac0"]["recipients"][0]["key"][SymmetricKey.SymPrm.K]),
        kid=test_input['mac0']['recipients'][0]["key"][CoseKey.Common.KID])

    cose_msg.key = key
    assert key.key_bytes == unhexlify(test_intermediate["CEK_hex"])

    assert cose_msg.verify_auth_tag()
