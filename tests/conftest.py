import base64
import json
import os
import pathlib

import pytest

from pycose.attributes import CoseHeaderParam, CoseAlgorithm

path_examples = os.path.join(pathlib.Path(__file__).parent.absolute(), 'examples')

aes_ccm_examples = os.path.join(path_examples, 'aes-ccm-examples')
aes_gcm_examples = os.path.join(path_examples, 'aes-gcm-examples')
encrypted_tests = os.path.join(path_examples, 'encrypted-tests')

algs_to_be_replaced = {
    'A128GCM': CoseAlgorithm.A128GCM,
    'A192GCM': CoseAlgorithm.A192GCM,
    'A256GCM': CoseAlgorithm.A256GCM,
    'AES-CCM-16-128/64': CoseAlgorithm.AES_CCM_16_64_128,
    'AES-CCM-16-256/64': CoseAlgorithm.AES_CCM_16_64_256,
    'AES-CCM-16-128/128': CoseAlgorithm.AES_CCM_16_128_128,
    'AES-CCM-64-128/128': CoseAlgorithm.AES_CCM_64_128_128,
    'AES-CCM-64-128/64': CoseAlgorithm.AES_CCM_64_64_128,
    'AES-CCM-64-256/64': CoseAlgorithm.AES_CCM_64_64_256,
    'AES-CCM-16-256/128': CoseAlgorithm.AES_CCM_16_128_256,
    'AES-CCM-64-256/128': CoseAlgorithm.AES_CCM_64_128_256,
}

params_to_be_replaced = {
    'ctyp': CoseHeaderParam.CONTENT_TYPE,
    'kid': CoseHeaderParam.KID,
    'alg': CoseHeaderParam.ALG,
}


@pytest.fixture
def protected_header(request):
    test_case = json.load(open(request.param, 'r'))
    _fix_header_algorithm_names(test_case, 'enveloped', 'protected')
    return test_case['input']['enveloped']['protected']


@pytest.fixture
def encrypt0_test_cases(request):
    test_input = json.load(open(request.param, 'r'))
    if 'encrypted' in test_input['input']:
        _fix_header_attribute_names(test_input, 'encrypted', 'protected')
        _fix_header_attribute_names(test_input, 'encrypted', 'unprotected')
        _fix_header_algorithm_names(test_input, 'encrypted', 'protected')
        _fix_header_algorithm_names(test_input, 'encrypted', 'unprotected')
        return test_input


@pytest.fixture
def encrypt_test_cases(request):
    test_input = json.load(open(request.param, 'r'))
    if 'enveloped' in test_input['input']:
        _fix_header_attribute_names(test_input, 'enveloped', 'protected')
        _fix_header_attribute_names(test_input, 'enveloped', 'unprotected')
        _fix_header_algorithm_names(test_input, 'enveloped', 'protected')
        _fix_header_algorithm_names(test_input, 'enveloped', 'unprotected')
        return test_input


def _fix_header_algorithm_names(input_data: dict, key: str, hdr_type: str) -> None:
    try:
        header_dict = input_data['input'][key][hdr_type]
    except KeyError:
        return

    header_dict = {k: (v if v not in algs_to_be_replaced else algs_to_be_replaced[v]) for k, v in header_dict.items()}
    input_data['input'][key][hdr_type] = header_dict


def _fix_header_attribute_names(input_data: dict, key: str, hdr_type: str):
    try:
        header_dict = input_data['input'][key][hdr_type]
    except KeyError:
        return

    header_dict = {(k if k not in params_to_be_replaced else params_to_be_replaced[k]): v for k, v in
                   header_dict.items()}
    input_data['input'][key][hdr_type] = header_dict

