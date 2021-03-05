from cose.algorithms import CoseAlgorithm, Direct, A128GCM, AESCCM1664128

from cose.headers import Algorithm


def test_header():
    alg_1 = Algorithm
    alg_2 = Algorithm

    assert alg_1 == alg_2
    assert id(alg_1) == id(alg_2)
    assert Algorithm == alg_2
    assert int(Algorithm()) == alg_2.identifier
    assert Algorithm.identifier == alg_2.identifier
    assert alg_1.fullname == "ALG"


def test_algorithm():
    gcm_1 = A128GCM
    gcm_2 = A128GCM
    ccm = AESCCM1664128

    assert ccm.identifier > gcm_1.identifier
    assert gcm_2 == gcm_1


def test_parsing():
    alg = CoseAlgorithm.from_id(-6)
    assert alg == Direct

    attr = Algorithm
    assert Direct == attr.value_parser(-6)
