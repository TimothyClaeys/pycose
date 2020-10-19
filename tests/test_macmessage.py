from binascii import unhexlify

from pytest import fixture, mark, skip

from cose import CoseMessage
from cose.attributes.algorithms import CoseAlgorithms
from cose.keys.cosekey import KeyOps
from cose.keys.symmetric import SymmetricKey
from cose.messages.macmessage import MacMessage
from cose.messages.recipient import CoseRecipient, RcptParams
from tests.conftest import generic_test_setup, create_cose_key, extract_alg


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
        external_aad=unhexlify(test_input['mac'].get("external", b'')))

    assert mac._mac_structure == unhexlify(test_intermediate["ToMac_hex"])

    alg = extract_alg(test_input["mac"])

    # set up the CEK and KEK
    cek = create_cose_key(SymmetricKey, test_input['mac']['recipients'][0]['key'], alg=alg, usage=KeyOps.MAC_CREATE)
    kek = create_cose_key(SymmetricKey, test_input['mac']['recipients'][0]['key'], alg=CoseAlgorithms.DIRECT.id,
                          usage=KeyOps.WRAP)

    assert cek.k == unhexlify(test_intermediate["CEK_hex"])

    recipient = test_input["mac"]["recipients"][0]
    recipient = CoseRecipient(
        phdr=recipient.get('protected', {}),
        uhdr=recipient.get('unprotected', {}),
        payload=cek.k)

    mac.recipients.append(recipient)

    # verify encoding (with automatic tag computation)
    if fail:
        assert mac.encode(cek, mac_params=[RcptParams(key=kek)]) != unhexlify(test_output)
    else:
        assert mac.encode(cek, mac_params=[RcptParams(key=kek)]) == unhexlify(test_output)


def test_mac_direct_decoding(setup_mac_tests: tuple) -> None:
    _, test_input, test_output, test_intermediate, fail = setup_mac_tests

    if fail:
        skip("invalid test input")

    msg: MacMessage = CoseMessage.decode(unhexlify(test_output))

    assert msg.phdr == test_input['mac'].get('protected', {})
    assert msg.uhdr == test_input['mac'].get('unprotected', {})
    assert msg.payload == test_input['plaintext'].encode('utf-8')

    # set up potential external data
    msg.external_aad = unhexlify(test_input['mac'].get("external", b''))
    assert msg._mac_structure == unhexlify(test_intermediate['ToMac_hex'])

    alg = extract_alg(test_input['mac'])
    cek = create_cose_key(SymmetricKey, test_input['mac']["recipients"][0]["key"], usage=KeyOps.MAC_VERIFY, alg=alg)
    assert cek.k == unhexlify(test_intermediate['CEK_hex'])

    # verify recipients
    for r1, r2 in zip(msg.recipients, test_input['mac']['recipients']):
        assert r1.phdr == r2.get('protected', {})
        assert r1.uhdr == r2.get('unprotected', {})

    assert msg.verify_tag(cek)

    # re-encode and verify we are back where we started
    kek = SymmetricKey(key_ops=KeyOps.WRAP, alg=CoseAlgorithms.DIRECT.id)
    cek.key_ops = KeyOps.MAC_CREATE
    assert msg.encode(key=cek, mac_params=[RcptParams(key=kek)]) == unhexlify(test_output)
