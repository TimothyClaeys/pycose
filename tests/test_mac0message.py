from binascii import unhexlify

from pytest import skip, fixture, mark

from pycose import CoseMessage
from pycose.keys.cosekey import KeyOps
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.mac0message import Mac0Message
from tests.conftest import generic_test_setup, create_cose_key, extract_alg


@fixture
def setup_mac0_tests(mac0_test_input: dict) -> tuple:
    return generic_test_setup(mac0_test_input)


@mark.decoding
def test_mac0_encoding(setup_mac0_tests: tuple) -> None:
    title, test_input, test_output, test_intermediate, fail = setup_mac0_tests

    mac0: Mac0Message = Mac0Message(
        phdr=test_input['mac0'].get('protected', {}),
        uhdr=test_input['mac0'].get('unprotected', {}),
        payload=test_input.get('plaintext', '').encode('utf-8'),
        external_aad=unhexlify(test_input['mac0'].get("external", b'')))

    assert mac0._mac_structure == unhexlify(test_intermediate["ToMac_hex"])

    cek = create_cose_key(
        SymmetricKey,
        test_input['mac0']["recipients"][0]["key"],
        alg=extract_alg(test_input["mac0"]),
        usage=KeyOps.MAC_CREATE)

    assert cek.k == unhexlify(test_intermediate["CEK_hex"])

    # verify encoding (with automatic tag computation)
    if fail:
        assert mac0.encode(key=cek) != unhexlify(test_output)
    else:
        assert mac0.encode(key=cek) == unhexlify(test_output)


def test_mac0_decoding(setup_mac0_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_mac0_tests

    if fail:
        skip("invalid test input")

    cose_msg: Mac0Message = CoseMessage.decode(unhexlify(test_output))

    assert cose_msg.phdr == test_input['mac0'].get('protected', {})
    assert cose_msg.uhdr == test_input['mac0'].get('unprotected', {})
    assert cose_msg.payload == test_input.get('plaintext', "").encode('utf-8')

    # set up potential external data
    cose_msg.external_aad = unhexlify(test_input['mac0'].get("external", b''))

    cek = create_cose_key(
        SymmetricKey,
        test_input['mac0']["recipients"][0]["key"],
        alg=extract_alg(test_input["mac0"]),
        usage=KeyOps.MAC_VERIFY)

    assert cek.k == unhexlify(test_intermediate["CEK_hex"])

    assert cose_msg.verify_tag(cek)
