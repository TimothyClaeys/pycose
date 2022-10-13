import os

import pytest

from pycose.algorithms import A128GCM
from pycose.exceptions import CoseIllegalKeyType, CoseInvalidKey
from pycose.keys import SymmetricKey, CoseKey
from pycose.keys.keyops import EncryptOp
from pycose.keys.keyparam import KpKty, SymKpK, KpAlg, KpKeyOps
from pycose.keys.keytype import KtySymmetric


###############################################################
# Symmetric key checks
###############################################################


def _is_valid_symmetric_key(key: SymmetricKey):
    return (KpKty in key and SymKpK in key) and (len(key.k) == 16 or len(key.k) == 24 or len(key.k) == 32)


@pytest.mark.parametrize('key_type, value',
                         [(KpKty, KtySymmetric), ('KTY', 'SYMMETRIC'), (1, 4),
                          (KpKty, 'SYMMETRIC'), (KpKty, 4),
                          ('KTY', KtySymmetric), ('KTY', 4),
                          (1, KtySymmetric), (1, 'SYMMETRIC')])
@pytest.mark.parametrize('key_bytes, random_bytes',
                         [(SymKpK, os.urandom(16)), ('K', os.urandom(16)), (-1, os.urandom(16))])
def test_symmetric_keys_from_dicts(key_type, value, key_bytes, random_bytes):
    d = {key_type: value, key_bytes: random_bytes}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_symmetric_key(cose_key)


@pytest.mark.parametrize('key_type, value',
                         [(KpKty, KtySymmetric), ('KTY', 'SYMMETRIC'), (1, 4),
                          (KpKty, 'SYMMETRIC'), (KpKty, 4),
                          ('KTY', KtySymmetric), ('KTY', 4),
                          (1, KtySymmetric), (1, 'SYMMETRIC')])
@pytest.mark.parametrize('key_bytes, random_bytes',
                         [(SymKpK, os.urandom(16)), ('K', os.urandom(16)), (-1, os.urandom(16))])
@pytest.mark.parametrize('alg, alg_value',
                         [(KpAlg, A128GCM), ('ALG', 'A128GCM'), (3, 1),
                          (KpAlg, 'A128GCM'), (KpAlg, 1),
                          ('ALG', A128GCM), ('ALG', 1),
                          (3, A128GCM), (3, 'A128GCM')])
def test_symmetric_keys_from_dicts_extended(key_type, value, key_bytes, random_bytes, alg, alg_value):
    d = {key_type: value, key_bytes: random_bytes, alg: alg_value}
    cose_key = CoseKey.from_dict(d)
    assert _is_valid_symmetric_key(cose_key)


@pytest.mark.parametrize('length', [16, 24, 32])
def test_symmetric_key_generation_encoding_decoding(length):
    trails = 10

    for i in range(trails):
        sym_test = SymmetricKey.generate_key(length)
        sym_encoded = sym_test.encode()
        sym_decoded = CoseKey.decode(sym_encoded)
        assert _is_valid_symmetric_key(sym_decoded)


@pytest.mark.parametrize('length', [16, 24, 32])
def test_symmetric_key_generation(length):
    key = SymmetricKey.generate_key(length)

    assert _is_valid_symmetric_key(key)


@pytest.mark.parametrize('length', [16, 24, 32])
def test_symmetric_key_construction(length):
    key = SymmetricKey(k=os.urandom(length))

    assert _is_valid_symmetric_key(key)


@pytest.mark.parametrize('length', [16, 24, 32])
def test_fail_on_missing_symmetric_kty(length):
    cose_key = {SymKpK: os.urandom(length)}

    with pytest.raises(CoseIllegalKeyType) as excinfo:
        CoseKey.from_dict(cose_key)

    assert "Could not decode CoseKey type, KpKty not set or unknown." in str(excinfo.value)


def test_fail_on_invalid_symmetric_key_length():
    cose_key = {KpKty: KtySymmetric, SymKpK: os.urandom(17)}

    with pytest.raises(CoseInvalidKey) as excinfo:
        CoseKey.from_dict(cose_key)

    assert "Key length should be either 16, 24, or 32 bytes" in str(excinfo.value)

    with pytest.raises(CoseInvalidKey) as excinfo:
        _ = SymmetricKey(k=os.urandom(17))

    assert "Key length should be either 16, 24, or 32 bytes" in str(excinfo.value)


def test_fail_on_missing_symkpk():
    cose_key = {KpKty: KtySymmetric, KpAlg: A128GCM}

    with pytest.raises(CoseInvalidKey) as excinfo:
        CoseKey.from_dict(cose_key)

    assert "SymKpK parameter cannot be None" in str(excinfo.value)


def test_remove_empty_keyops_list():
    cose_key = {KpKty: KtySymmetric, SymKpK: os.urandom(16), KpAlg: A128GCM, KpKeyOps: []}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps not in key


def test_existing_non_empty_keyops_list():
    cose_key = {KpKty: KtySymmetric, SymKpK: os.urandom(16), KpAlg: A128GCM, KpKeyOps: [EncryptOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKeyOps in key


def test_dict_operations_on_symmetric_key():
    cose_key = {KpKty: KtySymmetric, SymKpK: os.urandom(16), KpAlg: A128GCM, KpKeyOps: [EncryptOp]}

    key = CoseKey.from_dict(cose_key)

    assert KpKty in key
    assert 3 in key


def test_dict_valid_deletion():
    cose_key = {KpKty: KtySymmetric, SymKpK: os.urandom(16), KpAlg: A128GCM, KpKeyOps: [EncryptOp]}

    key = CoseKey.from_dict(cose_key)
    del key[KpAlg]
    assert KpAlg not in key

    key = CoseKey.from_dict(cose_key)
    del key[3]
    assert KpAlg not in key


def test_dict_invalid_deletion():
    cose_key = {KpKty: KtySymmetric, SymKpK: os.urandom(16), KpAlg: A128GCM, KpKeyOps: [EncryptOp]}

    key = CoseKey.from_dict(cose_key)

    with pytest.raises(CoseInvalidKey) as excinfo:
        del key[KpKty]


def test_unknown_key_attribute():
    key = SymmetricKey(k=os.urandom(32), optional_params={"subject_name": "signing key"})

    assert "subject_name" in key
    assert key['subject_name'] == "signing key"
