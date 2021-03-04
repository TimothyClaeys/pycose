import json
import pathlib
from binascii import unhexlify
from os import listdir
from os.path import join
from typing import List

import cbor2

from cose.keys import cosekey
from cose.algorithms import CoseAlgorithm
from cose.curves import CoseCurve
from cose.headers import CoseHeaderAttribute, IV, EphemeralKey, Algorithm, KID, PartyUNonce, StaticKey, ContentType
from cose.keys.keyparam import KpKty, SymKpK, OKPKpCurve, EC2KpCurve, KpKid, KpAlg, OKPKpD, EC2KpY, OKPKpX, EC2KpX, \
    EC2KpD
from cose.keys.keytype import KTY
from cose.messages.recipient import DirectEncryption, DirectKeyAgreement, KeyWrap, KeyAgreementWithKeyWrap
from cose.messages.signer import CoseSignature

p_tests = join(pathlib.Path(__file__).parent.absolute(), 'vectors')

test_encrypt0_files = [join(p_tests, 'encrypt0', f) for f in listdir(join(p_tests, 'encrypt0'))]
test_encrypt_direct_encryption_files = [join(p_tests, 'encrypt-direct-encryption', f) for f in
                                        listdir(join(p_tests, 'encrypt-direct-encryption'))]
test_encrypt_direct_key_agreement_files = [join(p_tests, 'encrypt-direct-key-agreement', f) for f in
                                           listdir(join(p_tests, 'encrypt-direct-key-agreement'))]
test_encrypt_key_wrap_files = [join(p_tests, 'encrypt-key-wrap', f) for f in listdir(join(p_tests, 'encrypt-key-wrap'))]
test_encrypt_key_agreement_key_wrap_files = [join(p_tests, 'encrypt-key-agreement-key-wrap', f) for f in
                                             listdir(join(p_tests, 'encrypt-key-agreement-key-wrap'))]

test_mac0_files = [join(p_tests, 'mac0', f) for f in listdir(join(p_tests, 'mac0'))]
test_mac_direct_encryption_files = [join(p_tests, 'mac-direct-encryption', f) for f in
                                    listdir(join(p_tests, 'mac-direct-encryption'))]

test_sign1_files = [join(p_tests, 'sign1', f) for f in listdir(join(p_tests, 'sign1'))]
test_sign_files = [join(p_tests, 'sign', f) for f in listdir(join(p_tests, 'sign'))]


def pytest_generate_tests(metafunc):
    if "test_encrypt0" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_encrypt0_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_encrypt0", test_suite, ids=ids)

    if "test_mac0" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_mac0_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_mac0", test_suite, ids=ids)

    if "test_sign1" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_sign1_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_sign1", test_suite, ids=ids)

    if "test_sign" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_sign_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_sign", test_suite, ids=ids)

    if "test_encrypt_direct_encryption_files" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_encrypt_direct_encryption_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_encrypt_direct_encryption_files", test_suite, ids=ids)

    if "test_mac_direct_encryption_files" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_mac_direct_encryption_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_mac_direct_encryption_files", test_suite, ids=ids)

    if "test_encrypt_direct_key_agreement_files" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_encrypt_direct_key_agreement_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_encrypt_direct_key_agreement_files", test_suite, ids=ids)

    if "test_encrypt_key_wrap_files" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_encrypt_key_wrap_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_encrypt_key_wrap_files", test_suite, ids=ids)

    if "test_encrypt_key_agreement_key_wrap_files" in metafunc.fixturenames:
        test_suite = load_cose_tests(test_encrypt_key_agreement_key_wrap_files)
        ids = [test_suite[i]['title'] for i in range(len(test_suite))]
        metafunc.parametrize("test_encrypt_key_agreement_key_wrap_files", test_suite, ids=ids)


def load_cose_tests(test_files) -> List[dict]:
    return [json.load(open(file, 'r'), object_hook=type_conv) for file in test_files]


def type_conv(d: dict) -> dict:
    if "__header__" in d:
        header = {}
        if 'ephemeral_key' in d:
            header[EphemeralKey] = d['ephemeral_key']
        if 'static_key' in d:
            header[StaticKey] = d['static_key']
        if 'alg' in d:
            header[Algorithm] = CoseAlgorithm.from_id(d['alg'])
        if 'kid' in d:
            header[KID] = d['kid'].encode('utf-8')
        if 'iv' in d:
            header[IV] = unhexlify(d['iv'])
        if 'party_u_nonce' in d:
            header[PartyUNonce] = unhexlify(d['party_u_nonce'])
        if 'ctype' in d:
            header[ContentType] = d['ctype']
        return header

    elif "__input__" in d or "__recipient__" in d:
        if 'alg' in d:
            d['alg'] = CoseAlgorithm.from_id(d['alg'])
        if 'plaintext' in d:
            d['plaintext'] = d['plaintext'].encode('utf-8')
        if 'external_aad' in d:
            d['external_aad'] = unhexlify(d['external_aad'])
        if 'iv' in d:
            d['iv'] = unhexlify(d['iv'])
        return d

    elif "__key__" in d:
        key = {KpKty: KTY.from_id(d['kty'])}
        if 'alg' in d:
            key[KpAlg] = CoseAlgorithm.from_id(d['alg'])
        if 'kid' in d:
            key[KpKid] = d["kid"].encode("utf-8")
        if 'crv' in d and d['kty'] == "EC2":
            key[EC2KpCurve] = CoseCurve.from_id(d['crv'])
        if 'crv' in d and d['kty'] == "OKP":
            key[OKPKpCurve] = CoseCurve.from_id(d['crv'])
        if 'k' in d:
            key[SymKpK] = unhexlify(d['k'])
        if 'x' in d and d['kty'] == "EC2":
            key[EC2KpX] = unhexlify(d['x'])
        if 'x' in d and d['kty'] == "OKP":
            key[OKPKpX] = unhexlify(d['x'])
        if 'y' in d and d['kty'] == "EC2":
            key[EC2KpY] = unhexlify(d['y'])
        if 'd' in d and d['kty'] == "EC2":
            key[EC2KpD] = unhexlify(d['d'])
        if 'd' in d and d['kty'] == "OKP":
            key[OKPKpD] = unhexlify(d['d'])

        key = cosekey.CoseKey.from_dict(key)
        return key

    elif '__encode_rcpt__' in d or '__encode_signer__' in d:
        d['protected'] = unhexlify(d['protected'])
        d['unprotected'] = {
            CoseHeaderAttribute.from_id(k1): cosekey.CoseKey.from_dict(
                {
                    k2: (unhexlify(v2) if k2 == -2 or k2 == -3 else v2) for k2, v2 in v1.items()
                }
            ) if isinstance(v1, dict) else v1 for k1, v1 in eval(d['unprotected']).items()
        }
        if PartyUNonce in d['unprotected']:
            d['unprotected'][PartyUNonce] = unhexlify(d['unprotected'][PartyUNonce])
        elif Algorithm in d['unprotected']:
            d['unprotected'][Algorithm] = CoseAlgorithm.from_id(d['unprotected'][Algorithm])

        if 'structure' in d:
            d['structure'] = unhexlify(d['structure'])
        if 'signature' in d:
            d['signature'] = unhexlify(d['signature'])
        if 'ciphertext' in d:
            d['ciphertext'] = unhexlify(d['ciphertext'])
        if 'secret' in d:
            d['secret'] = unhexlify(d['secret'])
        if "context" in d:
            d['context'] = unhexlify(d['context'])
        if 'kek' in d:
            d['kek'] = unhexlify(d['kek'])
        return d

    elif '__output__' in d:
        d['result'] = cbor2.loads(unhexlify(d['result']))
        d['protected'] = unhexlify(d['protected'])
        d['unprotected'] = {CoseHeaderAttribute.from_id(k): v for k, v in eval(d['unprotected']).items()}

        for k in d['unprotected'].keys():
            if k == Algorithm:
                d['unprotected'][k] = CoseAlgorithm.from_id(d['unprotected'][k])
            if k == IV:
                d['unprotected'][k] = unhexlify(d['unprotected'][k])
            if k == KID:
                d['unprotected'][k] = d['unprotected'][k]
            if k == PartyUNonce:
                d['unprotected'][k] = unhexlify(d['unprotected'][k])

        if "cek" in d:
            d['cek'] = unhexlify(d["cek"])

        if 'structure' in d:
            d['structure'] = unhexlify(d['structure'])
        d['ciphertext'] = unhexlify(d['ciphertext'])
        if 'tag' in d:
            d['tag'] = unhexlify(d['tag'])
        if 'signature' in d:
            d['signature'] = unhexlify(d['signature'])

        return d

    else:
        return d


def _setup_signers(test_vectors):
    signers = []
    for signer in test_vectors:
        signers.append(
            CoseSignature(
                phdr=signer['protected'],
                uhdr=signer['unprotected'],
                key=signer['signing_key'],
                external_aad=unhexlify(signer['external_aad'])))

    return signers


def _setup_direct_encryption_recipients(test_vectors):
    recipients = []
    for recipient in test_vectors:
        rcpt = DirectEncryption(phdr=recipient['protected'], uhdr=recipient['unprotected'])
        recipients.append(rcpt)

    return recipients


def _setup_direct_kex_recipients(test_vectors):
    recipients = []
    for recipient in test_vectors:
        rcpt = DirectKeyAgreement(phdr=recipient['protected'], uhdr=recipient['unprotected'])
        if 'ephemeral_sender_key' in recipient:
            rcpt.key = recipient['ephemeral_sender_key']
        elif 'static_sender_key' in recipient:
            rcpt.key = recipient['static_sender_key']

        if 'static_receiver_key' in recipient:
            rcpt.local_attrs = {StaticKey: recipient['static_receiver_key']}
        recipients.append(rcpt)

    return recipients


def _setup_key_wrap_recipients(test_vectors):
    recipients = []
    for recipient in test_vectors:
        rcpt = KeyWrap(phdr=recipient['protected'], uhdr=recipient['unprotected'])
        if 'secret_key' in recipient:
            rcpt.key = recipient['secret_key']
        recipients.append(rcpt)

    return recipients


def _setup_key_agreement_key_wrap(test_vectors):
    recipients = []
    for recipient in test_vectors:
        rcpt = KeyAgreementWithKeyWrap(phdr=recipient['protected'], uhdr=recipient['unprotected'])
        if 'ephemeral_sender_key' in recipient:
            rcpt.key = recipient['ephemeral_sender_key']
        elif 'static_sender_key' in recipient:
            rcpt.key = recipient['static_sender_key']

        if 'static_receiver_key' in recipient:
            rcpt.local_attrs = {StaticKey: recipient['static_receiver_key']}
        recipients.append(rcpt)

    return recipients
