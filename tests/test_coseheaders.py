from binascii import unhexlify

import pytest

from cose import CoseMessage, Enc0Message
from cose.attributes.algorithms import CoseAlgorithms
from cose.attributes.headers import CoseHeaderKeys
from cose.messages.enccommon import EncCommon

message_types = [(Enc0Message, CoseMessage), (Enc0Message, EncCommon)]


@pytest.mark.parametrize("cls, parent_cls", message_types, ids=['class_check_enc0_message', 'class_check_enc_message'])
def test_msg_creation(cls, parent_cls):
    cose_msg = cls()

    assert isinstance(cose_msg, parent_cls)


@pytest.mark.parametrize("params, encoded_phdr",
                         [
                             ({1: 10}, b'A1010A'),
                             ({CoseHeaderKeys.ALG: CoseAlgorithms.AES_CCM_16_64_128}, b'A1010A'),
                             ({1: CoseAlgorithms.AES_CCM_16_64_128}, b'A1010A'),
                             ({CoseHeaderKeys.ALG: 10}, b'A1010A'),
                             pytest.param({CoseHeaderKeys.ALG: None}, b'A1010A', marks=pytest.mark.xfail),
                             ({CoseHeaderKeys.ALG: CoseAlgorithms.AES_CCM_16_128_128}, b'A101181E')
                         ], ids=["unprotected_header_creation_" + str(i) for i in range(6)])
def test_indirect_phdr_creation(params, encoded_phdr):
    enc0_msg = Enc0Message()
    enc0_msg.phdr = params

    outcome = enc0_msg.encode_phdr()
    assert outcome == unhexlify(encoded_phdr)


@pytest.mark.parametrize("params, encoded_uhdr",
                         [
                             ({1: 10}, {1: 10}),
                             ({CoseHeaderKeys.ALG: 10}, {1: 10}),
                             ({CoseHeaderKeys.ALG: CoseAlgorithms.AES_CCM_16_64_128}, {1: 10}),
                             ({1: CoseAlgorithms.AES_CCM_16_64_128}, {1: 10}),
                             ({CoseHeaderKeys.ALG: 10, CoseHeaderKeys.IV: b'02D1F7E6F26C43D4868D87CE'},
                              {1: 10, 5: b'02D1F7E6F26C43D4868D87CE'}),
                             ({CoseHeaderKeys.PARTIAL_IV: b'61a7'}, {6: b'61a7'}),
                             pytest.param({1: None}, b'A1010A', marks=pytest.mark.xfail),
                             pytest.param(None, {}, marks=pytest.mark.xfail(reason="setter value must be of type dict"))
                         ], ids=["unprotected_header_creation_" + str(i) for i in range(8)])
def test_indirect_uhdr_creation(params, encoded_uhdr):
    enc0_msg = Enc0Message()
    enc0_msg.uhdr = params

    outcome = enc0_msg.encode_uhdr()
    assert outcome == encoded_uhdr


@pytest.mark.parametrize("params, encoded_uhdr",
                         [
                             ({1: 1, 5: b'02D1F7E6F26C43D4868D87CE'}, {1: 1, 5: b'02D1F7E6F26C43D4868D87CE'}),
                             ({CoseHeaderKeys.ALG: 10, CoseHeaderKeys.IV: b'02D1F7E6F26C43D4868D87CE'},
                              {1: 10, 5: b'02D1F7E6F26C43D4868D87CE'}),
                             ({CoseHeaderKeys.ALG: CoseAlgorithms.A256GCM, CoseHeaderKeys.IV: b'ae8987be9874f98ebb'},
                              {1: 3, 5: b'ae8987be9874f98ebb'}),
                         ], ids=["unprotected_header_update_" + str(i) for i in range(3)])
def test_update_uhdr(params, encoded_uhdr):
    enc0_msg = Enc0Message()
    enc0_msg.uhdr_update(params)

    outcome = enc0_msg.encode_uhdr()
    assert outcome == encoded_uhdr


@pytest.mark.parametrize("phdr, uhdr, payload", [("zefzef", "ezfzef", "zfezfzef")
                                                 ], ids=["cose_header_type_checks" + str(i) for i in range(1)])
def test_cose_header_type_checks(phdr: dict, uhdr: dict, payload: bytes) -> None:
    with pytest.raises(TypeError) as except_info:
        Enc0Message(phdr=phdr)
    assert "protected header should be of type 'dict'" in str(except_info)

    with pytest.raises(TypeError) as except_info:
        Enc0Message(uhdr=uhdr)
    assert "unprotected header should be of type 'dict'" in str(except_info)

    with pytest.raises(TypeError) as except_info:
        Enc0Message(payload=payload)
    assert "payload should be of type 'bytes'" in str(except_info)


@pytest.mark.parametrize("param1, param2, expected", [({1: 10}, {1: 1}, {1: 1})],
                         ids=['unprotected_header_overwrite_test_1'])
def test_overwrite_attr_uhdr(param1, param2, expected):
    enc0_msg = Enc0Message()
    enc0_msg.uhdr_update(param1)
    enc0_msg.uhdr_update(param2)

    assert enc0_msg.encode_uhdr() == expected


@pytest.mark.parametrize("param1, param2, expected", [({1: 1}, {1: 10}, b'A1010A')],
                         ids=['protected_header_overwrite_test_1'])
def test_overwrite_attr_phdr(param1, param2, expected):
    enc0_msg = Enc0Message()
    enc0_msg.phdr_update(param1)
    enc0_msg.phdr_update(param2)

    assert enc0_msg.encode_phdr() == unhexlify(expected)


@pytest.mark.parametrize("params, expected", [({1: -25}, b'a1013818'),
                                              ({1: CoseAlgorithms.ES256}, b'a10126'),
                                              ({'reserved': False, 2: ["reserved"]},
                                               b'a2687265736572766564f40281687265736572766564'),
                                              ({CoseHeaderKeys.ALG: CoseAlgorithms.EDDSA,
                                                CoseHeaderKeys.CONTENT_TYPE: 0}, b'A201270300'),
                                              (None, b'')
                                              ],
                         ids=["constructor_phdr_test_" + str(i) for i in range(5)])
def test_direct_phdr_creation(params, expected):
    enc0_msg = Enc0Message(phdr=params)
    assert enc0_msg.encode_phdr() == unhexlify(expected)


@pytest.mark.parametrize("params, expected",
                         [
                             ({1: CoseAlgorithms.DIRECT, CoseHeaderKeys.KID: b'our-secret'}, {1: -6, 4: b'our-secret'}),
                             ({CoseHeaderKeys.KID: 11}, {4: 11}),
                             (None, {})
                         ], ids=["constructor_phdr_test_" + str(i) for i in range(3)])
def test_direct_uhdr_creation(params, expected):
    enc0_msg = Enc0Message(uhdr=params)
    assert enc0_msg.encode_uhdr() == expected
