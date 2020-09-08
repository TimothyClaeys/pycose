import json
import os
import pathlib
from binascii import unhexlify
from typing import List, Type, Union, Optional, Tuple

from pytest import skip

from pycose.attributes.algorithms import CoseAlgorithms, CoseEllipticCurves
from pycose.attributes.headers import CoseHeaderKeys
from pycose.keys.cosekey import KTY, CoseKey, KeyOps
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP
from pycose.keys.symmetric import SymmetricKey

path_examples = os.path.join(pathlib.Path(__file__).parent.absolute(), 'examples')

mac0_test_vector_dirs = [os.path.join(path_examples, "mac0-tests")]
mac_test_vector_dirs = [
    os.path.join(path_examples, "mac-tests"),
    os.path.join(path_examples, "hmac-examples"),
    os.path.join(path_examples, "cbc-mac-examples")]
mac_hkdf_hmac_direct_test_vectors_dirs = [os.path.join(path_examples, "hkdf-hmac-sha-examples")]
enc0_test_vector_dirs = [
    os.path.join(path_examples, 'aes-ccm-examples'),
    os.path.join(path_examples, 'aes-gcm-examples'),
    os.path.join(path_examples, 'encrypted-tests')]
enc_test_vector_dirs = [
    os.path.join(path_examples, 'aes-ccm-examples'),
    os.path.join(path_examples, 'aes-gcm-examples'),
    os.path.join(path_examples, 'enveloped-tests')]
ecdh_direct_test_vector_dirs = [os.path.join(path_examples, 'ecdh-direct-examples')]
ecdh_wrap_test_vector_dirs = [os.path.join(path_examples, 'ecdh-wrap-examples')]
x25519_direct_test_vector_dirs = [os.path.join(path_examples, 'X25519-tests')]
triple_layer_enc_test_vector_dirs = [os.path.join(path_examples, 'RFC8152')]
sign1_test_vector_dirs = [os.path.join(path_examples, "sign1-tests")]
sign_test_vector_dirs = [os.path.join(path_examples, "sign-tests")]
countersign_test_vector_dirs = [os.path.join(path_examples, 'countersign')]

algs_to_be_replaced = {
    'A128KW': CoseAlgorithms.A128KW.id,
    'A192KW': CoseAlgorithms.A128KW.id,
    'A256KW': CoseAlgorithms.A128KW.id,
    'A128GCM': CoseAlgorithms.A128GCM.id,
    'A192GCM': CoseAlgorithms.A192GCM.id,
    'A256GCM': CoseAlgorithms.A256GCM.id,
    'AES-CCM-16-128/64': CoseAlgorithms.AES_CCM_16_64_128.id,
    'AES-CCM-16-256/64': CoseAlgorithms.AES_CCM_16_64_256.id,
    'AES-CCM-16-128/128': CoseAlgorithms.AES_CCM_16_128_128.id,
    'AES-CCM-64-128/128': CoseAlgorithms.AES_CCM_64_128_128.id,
    'AES-CCM-64-128/64': CoseAlgorithms.AES_CCM_64_64_128.id,
    'AES-CCM-64-256/64': CoseAlgorithms.AES_CCM_64_64_256.id,
    'AES-CCM-16-256/128': CoseAlgorithms.AES_CCM_16_128_256.id,
    'AES-CCM-64-256/128': CoseAlgorithms.AES_CCM_64_128_256.id,
    'direct': CoseAlgorithms.DIRECT.id,
    "ECDH-ES-512": CoseAlgorithms.ECDH_ES_HKDF_512.id,
    "ECDH-ES": CoseAlgorithms.ECDH_ES_HKDF_256.id,
    "ECDH-SS": CoseAlgorithms.ECDH_SS_HKDF_256.id,
    "ECDH-SS-256": CoseAlgorithms.ECDH_SS_HKDF_256.id,
    "ECDH-SS-512": CoseAlgorithms.ECDH_SS_HKDF_512.id,
    "ECDH-SS-A192KW": CoseAlgorithms.ECDH_SS_A192KW.id,
    "ECDH-ES-A256KW": CoseAlgorithms.ECDH_ES_A256KW.id,
    "ECDH-SS-A128KW": CoseAlgorithms.ECDH_SS_A128KW.id,
    "ECDH-ES-A192KW": CoseAlgorithms.ECDH_ES_A192KW.id,
    "ECDH-ES-A128KW": CoseAlgorithms.ECDH_ES_A128KW.id,
    "ECDH-SS-A256KW": CoseAlgorithms.ECDH_SS_A256KW.id,
    "HS256": CoseAlgorithms.HMAC_256_256.id,
    "HS384": CoseAlgorithms.HMAC_384_384.id,
    "HS512": CoseAlgorithms.HMAC_512_512.id,
    "HS256/64": CoseAlgorithms.HMAC_256_64.id,
    "AES-MAC-256/64": CoseAlgorithms.AES_MAC_256_64.id,
    "AES-MAC-128/64": CoseAlgorithms.AES_MAC_128_64.id,
    "AES-MAC-128/128": CoseAlgorithms.AES_MAC_128_128.id,
    "AES-MAC-256/128": CoseAlgorithms.AES_MAC_256_128.id,
    "HKDF-HMAC-SHA-256": CoseAlgorithms.DIRECT_HKDF_SHA_256.id,
    "HKDF-HMAC-SHA-512": CoseAlgorithms.DIRECT_HKDF_SHA_512.id,
    "ES256": CoseAlgorithms.ES256.id,
    "ES384": CoseAlgorithms.ES384.id,
    "ES512": CoseAlgorithms.ES512.id,
}

params_to_be_replaced = {
    'ctyp': CoseHeaderKeys.CONTENT_TYPE,
    'kid': CoseHeaderKeys.KID,
    'alg': CoseHeaderKeys.ALG,
    'partialIV_hex': CoseHeaderKeys.PARTIAL_IV,
}

key_param_to_be_replaced = {
    'kty': CoseKey.Common.KTY,
    'k': SymmetricKey.SymPrm.K,
    'x': EC2.EC2Prm.X,
    'x_hex': EC2.EC2Prm.X,
    'y_hex': EC2.EC2Prm.Y,
    'd_hex': EC2.EC2Prm.D,
    'y': EC2.EC2Prm.Y,
    'd': EC2.EC2Prm.D,
    'crv': EC2.EC2Prm.CRV,
    'kid': CoseKey.Common.KID
}

key_attr_to_be_replaced = {
    "EC": KTY.EC2,
    "OKP": KTY.OKP,
    "P-256": CoseEllipticCurves.P_256,
    "P-384": CoseEllipticCurves.P_384,
    "P-521": CoseEllipticCurves.P_521,
    "X25519": CoseEllipticCurves.X25519,
    "X448": CoseEllipticCurves.X448,
    "oct": KTY.SYMMETRIC,
}


def pytest_generate_tests(metafunc):
    if "mac0_test_input" in metafunc.fixturenames:
        test_suite = mac0_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("mac0_test_input", test_suite, ids=ids)
    if "mac_test_input" in metafunc.fixturenames:
        test_suite = mac_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("mac_test_input", test_suite, ids=ids)
    if "encrypt0_test_input" in metafunc.fixturenames:
        test_suite = encrypt0_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("encrypt0_test_input", test_suite, ids=ids)
    if "encrypt_test_input" in metafunc.fixturenames:
        test_suite = encrypt_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("encrypt_test_input", test_suite, ids=ids)
    if "encrypt_ecdh_direct_test_input" in metafunc.fixturenames:
        test_suite = encrypt_ecdh_direct_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("encrypt_ecdh_direct_test_input", test_suite, ids=ids)
    if "encrypt_ecdh_wrap_test_input" in metafunc.fixturenames:
        test_suite = encrypt_ecdh_wrap_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("encrypt_ecdh_wrap_test_input", test_suite, ids=ids)
    if "encrypt_x25519_direct_test_input" in metafunc.fixturenames:
        test_suite = encrypt_x25519_direct_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("encrypt_x25519_direct_test_input", test_suite, ids=ids)
    if "encrypt_triple_layer_test_input" in metafunc.fixturenames:
        test_suite = encrypt_triple_layer_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("encrypt_triple_layer_test_input", test_suite, ids=ids)
    if "encrypt_hkdf_hmac_direct_test_input" in metafunc.fixturenames:
        test_suite = encrypt_hkdf_hmac_direct_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("encrypt_hkdf_hmac_direct_test_input", test_suite, ids=ids)
    if "sign1_test_input" in metafunc.fixturenames:
        test_suite = sign1_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("sign1_test_input", test_suite, ids=ids)
    if "sign_test_input" in metafunc.fixturenames:
        test_suite = sign_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("sign_test_input", test_suite, ids=ids)
    if "countersign_test_input" in metafunc.fixturenames:
        test_suite = countersign_tests()
        ids = [test['title'] for test in test_suite]
        metafunc.parametrize("countersign_test_input", test_suite, ids=ids)


def generic_test_setup(generic_test_input: dict) -> tuple:
    try:
        title = generic_test_input['title']
        test_input = generic_test_input['input']
        test_output = generic_test_input['output']['cbor']
        test_intermediate = generic_test_input['intermediates']
    except (KeyError, TypeError):
        return skip("Invalid test input")

    if 'fail' in generic_test_input or "failures" in test_input:
        fail = True
    else:
        fail = False

    return title, test_input, test_output, test_intermediate, fail


def mac0_tests():
    return _build_test_cases(['mac0'], mac0_test_vector_dirs)


def mac_tests():
    return _build_test_cases(['mac'], mac_test_vector_dirs)


def encrypt0_tests():
    return _build_test_cases(['encrypted'], enc0_test_vector_dirs)


def encrypt_tests():
    return _build_test_cases(['enveloped'], enc_test_vector_dirs)


def encrypt_ecdh_direct_tests():
    return _build_test_cases(['enveloped'], ecdh_direct_test_vector_dirs)


def encrypt_ecdh_wrap_tests():
    return _build_test_cases(['enveloped'], ecdh_wrap_test_vector_dirs)


def encrypt_x25519_direct_tests():
    return _build_test_cases(['enveloped'], x25519_direct_test_vector_dirs)


def encrypt_triple_layer_tests():
    return _build_test_cases(['enveloped'], triple_layer_enc_test_vector_dirs,
                             os.path.join("RFC8152", "Appendix_B.json"))


def encrypt_hkdf_hmac_direct_tests():
    return _build_test_cases(['enveloped'], mac_hkdf_hmac_direct_test_vectors_dirs)


def sign1_tests():
    return _build_test_cases(['sign0'], sign1_test_vector_dirs)


def sign_tests():
    return _build_test_cases(['sign'], sign_test_vector_dirs)


def countersign_tests():
    return _build_test_cases(['sign'], sign_test_vector_dirs)


def _build_test_cases(keys: List[str], test_dirs: List[str], single_file: Optional[str] = None):
    test_files = [os.path.join(path_examples, td, file) for td in test_dirs for file in os.listdir(td)]

    if single_file is not None and os.path.join(path_examples, single_file) in test_files:
        test_files = [os.path.join(path_examples, single_file)]

    fixed_test_cases = []

    for file in test_files:
        test_case = json.load(open(file, 'r'))
        for key in keys:
            if key in test_case['input']:
                _fix_header_attribute_names(test_case['input'][key], 'protected')
                _fix_header_attribute_names(test_case['input'][key], 'unprotected')
                _fix_header_algorithm_names(test_case['input'][key], 'protected')
                _fix_header_algorithm_names(test_case['input'][key], 'unprotected')

                try:
                    recipients = test_case['input'][key]['recipients']
                    _fix_recipients(recipients)
                except KeyError:
                    pass

                try:
                    signers = test_case['input'][key]['signers']
                    _fix_recipients(signers)
                except KeyError:
                    pass

                try:
                    _fix_key_object(test_case['input'][key], 'key')
                except KeyError:
                    pass

                fixed_test_cases.append(test_case)

    return fixed_test_cases


def _fix_recipients(recipients: dict) -> None:
    for r_info in recipients:
        _fix_header_attribute_names(r_info, 'unprotected')
        _fix_header_attribute_names(r_info, 'protected')
        _fix_header_algorithm_names(r_info, 'unprotected')
        _fix_header_algorithm_names(r_info, 'protected')

        if 'key' in r_info:
            _fix_key_object(r_info, 'key')

        if 'sender_key' in r_info:
            _fix_key_object(r_info, 'sender_key')

        if 'recipients' in r_info:
            _fix_recipients(r_info['recipients'])

        if 'signers' in r_info:
            _fix_recipients(r_info['signers'])


def _fix_key_object(data: dict, key: str) -> None:
    updated = {
        (key_param_to_be_replaced[k] if k in key_param_to_be_replaced else k):
            key_attr_to_be_replaced[v] if v in key_attr_to_be_replaced else v for k, v in data[key].items()
    }
    if CoseKey.Common.KID in updated:
        updated[CoseKey.Common.KID] = updated[CoseKey.Common.KID].encode('utf-8')

    data[key] = updated


def _fix_header_algorithm_names(data: dict, key) -> None:
    try:
        header_dict = data[key]
    except KeyError:
        return

    temp = None
    if "epk" in header_dict:
        _fix_key_object(header_dict, "epk")
        temp = header_dict["epk"]
        if EC2.EC2Prm.X in temp and isinstance(temp[EC2.EC2Prm.X], str):
            temp[EC2.EC2Prm.X] = CoseKey.base64decode(temp[EC2.EC2Prm.X])
        if EC2.EC2Prm.Y in temp and isinstance(temp[EC2.EC2Prm.Y], str):
            temp[EC2.EC2Prm.Y] = CoseKey.base64decode(temp[EC2.EC2Prm.Y])
        del header_dict["epk"]

    header_dict = {k: (v if v not in algs_to_be_replaced else algs_to_be_replaced[v]) for k, v in header_dict.items()}

    if temp is not None:
        header_dict[CoseHeaderKeys.EPHEMERAL_KEY] = temp
    data[key] = header_dict


def _fix_header_attribute_names(data: dict, key) -> None:
    try:
        header_dict = data[key]
    except KeyError:
        return

    header_dict = {(k if k not in params_to_be_replaced else params_to_be_replaced[k]): v for k, v in
                   header_dict.items()}

    if CoseHeaderKeys.KID in header_dict and type(header_dict[CoseHeaderKeys.KID]) == str:
        header_dict[CoseHeaderKeys.KID] = header_dict[CoseHeaderKeys.KID].encode('utf-8')
    if CoseHeaderKeys.PARTIAL_IV in header_dict and type(header_dict[CoseHeaderKeys.PARTIAL_IV]) == str:
        header_dict[CoseHeaderKeys.PARTIAL_IV] = unhexlify(header_dict[CoseHeaderKeys.PARTIAL_IV].encode('utf-8'))
    data[key] = header_dict


def create_cose_key(key_type: Type[CoseKey],
                    input_data: dict,
                    alg: Optional[CoseAlgorithms] = None,
                    usage: Optional[KeyOps] = None) -> Union[EC2, SymmetricKey, OKP]:
    if key_type == EC2:
        key = EC2(
            kid=input_data.get(CoseKey.Common.KID),
            key_ops=usage,
            alg=alg,
            crv=input_data.get(EC2.EC2Prm.CRV),
            x=CoseKey.base64decode(input_data.get(EC2.EC2Prm.X)),
            y=CoseKey.base64decode(input_data.get(EC2.EC2Prm.Y)),
            d=CoseKey.base64decode(input_data.get(EC2.EC2Prm.D)),
        )
    elif key_type == SymmetricKey:
        key = SymmetricKey(
            kid=input_data.get(CoseKey.Common.KID),
            alg=alg,
            key_ops=usage,
            k=CoseKey.base64decode(input_data.get(SymmetricKey.SymPrm.K))
        )
    elif key_type == OKP:
        key = OKP(
            kid=input_data.get(CoseKey.Common.KID),
            alg=alg,
            key_ops=usage,
            crv=input_data.get(OKP.OKPPrm.CRV),
            x=CoseKey.base64decode(input_data.get(OKP.OKPPrm.X)),
            d=CoseKey.base64decode(input_data.get(OKP.OKPPrm.D)),
        )
    else:
        raise Exception

    return key


def extract_phdr(test_input: dict, key: str) -> dict:
    return test_input[key].get('protected', {})


def extract_uhdr(test_input: dict, key: str, rng_index=0) -> dict:
    base = test_input[key].get('unprotected', {})

    if key == 'encrypted' or key == 'enveloped':
        if 'rng_stream' in test_input:
            base.update({CoseHeaderKeys.IV: unhexlify(test_input['rng_stream'][rng_index])})
    return base


def extract_unsent_nonce(test_input: dict, key: str) -> Optional[bytes]:
    if 'unsent' in test_input[key]:
        return unhexlify(test_input[key]['unsent']['IV_hex'])
    else:
        return b''


def extract_nonce(test_input: dict, rng_index=0) -> bytes:
    if 'rng_stream' in test_input:
        return unhexlify(test_input['rng_stream'][rng_index])
    else:
        return b""


def extract_alg(test_input: dict) -> CoseAlgorithms:
    alg = test_input.get('protected', {}).get(CoseHeaderKeys.ALG)
    if alg is None:
        alg = test_input.get('unprotected', {}).get(CoseHeaderKeys.ALG)

    return alg


def setup_ec_receiver_keys(recipient: dict, received_key_obj) -> Tuple[EC2, EC2]:
    alg = recipient.get("protected", {}).get(CoseHeaderKeys.ALG)
    if alg is None:
        alg = recipient.get("unprotected", {}).get(CoseHeaderKeys.ALG)

    rcvr_static_key = EC2(
        kid=recipient['key'][CoseKey.Common.KID],
        crv=recipient['key'][EC2.EC2Prm.CRV],
        alg=alg,
        x=CoseKey.base64decode(recipient['key'][EC2.EC2Prm.X]),
        y=CoseKey.base64decode(recipient['key'][EC2.EC2Prm.Y]),
        d=CoseKey.base64decode(recipient['key'][EC2.EC2Prm.D]),
    )

    # create CoseKey object for the sender key
    if 'sender_key' in recipient:
        sender_key = EC2(
            alg=alg,
            crv=recipient["sender_key"][EC2.EC2Prm.CRV],
            x=CoseKey.base64decode(recipient['sender_key'][EC2.EC2Prm.X]),
            y=CoseKey.base64decode(recipient['sender_key'][EC2.EC2Prm.Y]))
    else:
        sender_key = received_key_obj

    return rcvr_static_key, sender_key


def setup_okp_receiver_keys(recipient: dict, received_key_obj) -> Tuple[OKP, OKP]:
    alg = recipient.get("protected", {}).get(CoseHeaderKeys.ALG)
    if alg is None:
        alg = recipient.get("unprotected", {}).get(CoseHeaderKeys.ALG)

    rcvr_static_key = OKP(
        kid=recipient['key'][CoseKey.Common.KID],
        crv=recipient['key'][OKP.OKPPrm.CRV],
        alg=alg,
        x=unhexlify(recipient['key'][OKP.OKPPrm.X]),
        d=unhexlify(recipient['key'][OKP.OKPPrm.D]))

    # create CoseKey object for the sender key
    if 'sender_key' in recipient:
        sender_key = OKP(
            alg=alg,
            crv=recipient["sender_key"][OKP.OKPPrm.CRV],
            x=unhexlify(recipient['sender_key'][OKP.OKPPrm.X]))
    else:
        sender_key = received_key_obj

    return rcvr_static_key, sender_key
