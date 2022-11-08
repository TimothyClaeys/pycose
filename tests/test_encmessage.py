import cbor2

from pycose import headers
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import EncryptOp, DecryptOp
from pycose.keys.rsa import RSAKey
from pycose.messages.encmessage import EncMessage
from tests.conftest import _setup_direct_encryption_recipients, _setup_direct_kex_recipients, \
    _setup_key_wrap_recipients, _setup_key_agreement_key_wrap


def test_encrypt_direct_encryption_encoding(test_encrypt_direct_encryption_files):
    test_input = test_encrypt_direct_encryption_files['input']
    test_output = test_encrypt_direct_encryption_files['output']

    recipients = _setup_direct_encryption_recipients(test_input['recipients'])

    msg = EncMessage(test_input['protected'], test_input['unprotected'], test_input['plaintext'], recipients=recipients)

    key = CoseKey.from_dict(test_encrypt_direct_encryption_files["cek"])
    key.key_ops = [EncryptOp]

    msg.key = key

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._enc_structure == test_output['structure']

    assert cbor2.loads(msg.encode()) == test_output['result']


def test_encrypt_direct_encryption_decoding(test_encrypt_direct_encryption_files):
    test_output = test_encrypt_direct_encryption_files['output']
    test_input = test_encrypt_direct_encryption_files['input']

    msg = EncMessage.decode(cbor2.dumps((test_output['result'])))

    key = CoseKey.from_dict(test_encrypt_direct_encryption_files["cek"])
    key.key_ops = [DecryptOp]

    msg.key = key

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    for r in msg.recipients:
        assert msg.decrypt(r) == test_input['plaintext']


def test_encrypt_direct_key_agreement_encoding(test_encrypt_direct_key_agreement_files):
    test_input = test_encrypt_direct_key_agreement_files['input']
    test_output = test_encrypt_direct_key_agreement_files['output']

    recipients = _setup_direct_kex_recipients(test_input['recipients'])

    msg = EncMessage(test_input['protected'], test_input['unprotected'], test_input['plaintext'], recipients=recipients)

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._enc_structure == test_output['structure']

    # test intermediate results
    for r, r_output in zip(msg.recipients, test_output['recipients']):
        assert r.phdr_encoded == r_output['protected']
        assert r.uhdr_encoded == r_output['unprotected']
        assert r.get_kdf_context(msg.get_attr(headers.Algorithm)).encode() == r_output['context']

    assert msg.encrypt() == test_output['ciphertext']
    assert cbor2.loads(msg.encode()) == test_output['result']


def test_encrypt_direct_key_agreement_decoding(test_encrypt_direct_key_agreement_files):
    test_output = test_encrypt_direct_key_agreement_files['output']
    test_input = test_encrypt_direct_key_agreement_files['input']

    msg = EncMessage.decode(cbor2.dumps((test_output['result'])))

    assert msg._enc_structure == test_output['structure']

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    # test intermediate results
    for k, (r, r_output) in enumerate(zip(msg.recipients, test_output['recipients'])):
        assert r.phdr_encoded == r_output['protected']
        assert r.uhdr_encoded == r_output['unprotected']
        assert r.get_kdf_context(msg.get_attr(headers.Algorithm)).encode() == r_output['context']
        r.key = test_input['recipients'][k]['static_receiver_key']

    for r in msg.recipients:
        assert msg.decrypt(r) == test_input['plaintext']


def test_encrypt_key_wrap_encoding(test_encrypt_key_wrap_files):
    test_input = test_encrypt_key_wrap_files['input']
    test_output = test_encrypt_key_wrap_files['output']

    recipients = _setup_key_wrap_recipients(test_input['recipients'])

    msg = EncMessage(test_input['protected'], test_input['unprotected'], test_input['plaintext'], recipients=recipients)

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._enc_structure == test_output['structure']

    # test intermediate results
    for i, (r, r_output) in enumerate(zip(msg.recipients, test_output['recipients'])):
        assert r.phdr_encoded == r_output['protected']
        assert r.uhdr_encoded == r_output['unprotected']
        r.payload = test_encrypt_key_wrap_files['random_key'].k
        if not isinstance(r.key, RSAKey):
            assert r.encrypt(msg.get_attr(headers.Algorithm)) == test_output['recipients'][i]['ciphertext']

    assert msg.encrypt() == test_output['ciphertext']
    # remove signature for probabilistic behavior
    do_tag = test_encrypt_key_wrap_files.get('cbor_tag', True)
    msg_dec = cbor2.loads(msg.encode(tag=do_tag))
    test_dec = test_output['result']
    if isinstance(r.key, RSAKey):
        msg = msg_dec.value if do_tag else msg_dec
        for recip in msg[3]:
            recip[2] = b''

        msg = test_dec.value if do_tag else test_dec
        for recip in msg[3]:
            recip[2] = b''
    assert msg_dec == test_dec


def test_encrypt_key_wrap_decoding(test_encrypt_key_wrap_files):
    test_input = test_encrypt_key_wrap_files['input']
    test_output = test_encrypt_key_wrap_files['output']

    msg = EncMessage.decode(cbor2.dumps((test_output['result'])))

    assert msg._enc_structure == test_output['structure']

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    # test intermediate results
    for i, (r, r_output) in enumerate(zip(msg.recipients, test_output['recipients'])):
        assert r.phdr_encoded == r_output['protected']
        assert r.uhdr_encoded == r_output['unprotected']
        assert r.payload == r_output['ciphertext']
        # set the key
        r.key = test_input['recipients'][i]['secret_key']
        assert r.decrypt(msg.get_attr(headers.Algorithm)) == test_encrypt_key_wrap_files['random_key'].k

    for r in msg.recipients:
        assert msg.decrypt(r) == test_input['plaintext']


def test_encrypt_key_agreement_key_wrap_encoding(test_encrypt_key_agreement_key_wrap_files):
    test_input = test_encrypt_key_agreement_key_wrap_files['input']
    test_output = test_encrypt_key_agreement_key_wrap_files['output']

    recipients = _setup_key_agreement_key_wrap(test_input['recipients'])

    msg = EncMessage(test_input['protected'], test_input['unprotected'], test_input['plaintext'], recipients=recipients)

    assert msg._enc_structure == test_output['structure']

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    for i, (r, r_output) in enumerate(zip(msg.recipients, test_output['recipients'])):
        r.payload = test_encrypt_key_agreement_key_wrap_files['random_key'].k
        assert r.phdr_encoded == r_output['protected']
        assert r.uhdr_encoded == r_output['unprotected']
        assert r.get_kdf_context((r.get_attr(headers.Algorithm)).get_key_wrap_func()).encode() == r_output['context']
        assert r.encrypt((r.get_attr(headers.Algorithm)).get_key_wrap_func()) == r_output['ciphertext']

    assert msg.encrypt() == test_output['ciphertext']
    assert cbor2.loads(msg.encode()) == test_output['result']


def test_encrypt_key_agreement_key_wrap_decoding(test_encrypt_key_agreement_key_wrap_files):
    test_input = test_encrypt_key_agreement_key_wrap_files['input']
    test_output = test_encrypt_key_agreement_key_wrap_files['output']

    msg = EncMessage.decode(cbor2.dumps((test_output['result'])))

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    assert msg._enc_structure == test_output['structure']

    # test intermediate results
    for i, (r, r_output) in enumerate(zip(msg.recipients, test_output['recipients'])):
        # this should actually be static_receiver_key but the test vector is wrong and messed it up
        r.key = test_input['recipients'][i]['static_receiver_key']
        assert r.phdr_encoded == r_output['protected']
        assert r.uhdr_encoded == r_output['unprotected']
        assert r.payload == r_output['ciphertext']
        assert r.get_kdf_context((r.get_attr(headers.Algorithm)).get_key_wrap_func()).encode() == r_output['context']
        assert r.decrypt((r.get_attr(headers.Algorithm)).get_key_wrap_func()) == \
               test_encrypt_key_agreement_key_wrap_files['random_key'].k

    for r in msg.recipients:
        assert msg.decrypt(r) == test_input['plaintext']
