from binascii import unhexlify

from pytest import fixture, mark, skip

from pycose import CoseMessage
from pycose.cosekey import SymmetricKey, CoseKey, KeyOps
from pycose.macmessage import MacMessage
from pycose.recipient import CoseRecipient
from tests.conftest import generic_test_setup, create_cose_key


@fixture
def setup_mac_tests(mac_test_input: dict) -> tuple:
    return generic_test_setup(mac_test_input)


@mark.decoding
def test_mac_direct_encoding(setup_mac_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_mac_tests

    mac = MacMessage(
        phdr=test_input['mac'].get('protected', {}),
        uhdr=test_input['mac'].get('unprotected', {}),
        payload=test_input.get('plaintext', '').encode('utf-8'),
        external_aad=unhexlify(test_input['mac'].get("external", b''))
    )

    assert mac._mac_structure == unhexlify(test_intermediate["ToMac_hex"])

    key = create_cose_key(SymmetricKey, test_input['mac']["recipients"][0]["key"], usage=KeyOps.MAC_CREATE)
    assert key.key_bytes == unhexlify(test_intermediate["CEK_hex"])

    recipient = test_input["mac"]["recipients"][0]
    recipient = CoseRecipient(
        phdr=recipient.get('protected', {}),
        uhdr=recipient.get('unprotected', {}),
        payload=key.key_bytes
    )

    mac.recipients.append(recipient)

    mac.key = key

    # verify encoding (with automatic tag computation)
    if fail:
        assert mac.encode() != unhexlify(test_output)
    else:
        assert mac.encode() == unhexlify(test_output)


def test_mac_direct_decoding(setup_mac_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_mac_tests

    if fail:
        skip("invalid test input")

    cose_msg = CoseMessage.decode(unhexlify(test_output))

    assert cose_msg.phdr == test_input['mac'].get('protected', {})
    assert cose_msg.uhdr == test_input['mac'].get('unprotected', {})
    assert cose_msg.payload == test_input['plaintext'].encode('utf-8')

    # set up potential external data
    cose_msg.external_aad = unhexlify(test_input['mac'].get("external", b''))
    assert cose_msg._mac_structure == unhexlify(test_intermediate['ToMac_hex'])

    key = create_cose_key(SymmetricKey, test_input['mac']["recipients"][0]["key"], usage=KeyOps.MAC_VERIFY)
    assert key.key_bytes == unhexlify(test_intermediate["CEK_hex"])

    # verify recipients
    for r1, r2 in zip(cose_msg.recipients, test_input['mac']['recipients']):
        assert r1.phdr == r2.get('protected', {})
        assert r1.uhdr == r2.get('unprotected', {})

    try:
        assert cose_msg.verify_auth_tag()
    except AttributeError:
        pass

    cose_msg.key = key

    assert cose_msg.verify_auth_tag()


