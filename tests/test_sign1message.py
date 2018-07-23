import unittest
from binascii import unhexlify

from pycose.sign1message import Sign1Message


class CoseSign1Tests(unittest.TestCase):
    """tests for cose_mac0 message types"""

    header_params = \
        {
            'hash256/64_p': ['alg', 'HS256/64', 'PROTECTED', b'\xa1\x01\x04'],
            'hash256_p': ['alg', 'HS256', 'PROTECTED', b'\xa1\x01\x05'],
            'hash384_p': ['alg', 'HS384', 'PROTECTED', b'\xa1\x01\x06'],
            'hash512_p': ['alg', 'HS512', 'PROTECTED', b'\xa1\x01\x07'],
            'hash256/64_u': ['alg', 'HS256/64', 'UNPROTECTED', {1: 4}],
            'hash256_u': ['alg', 'HS256', 'UNPROTECTED', {1: 5}],
            'hash384_u': ['alg', 'HS384', 'UNPROTECTED', {1: 6}],
            'hash512_u': ['alg', 'HS512', 'UNPROTECTED', {1: 7}],
            'aes128/64_p': ['alg', 'AES-MAC128/64', 'PROTECTED', b'\xa1\x01\x0e'],
            'aes256/64_p': ['alg', 'AES-MAC256/64', 'PROTECTED', b'\xa1\x01\x0f'],
            'aes128/128_p': ['alg', 'AES-MAC128/128', 'PROTECTED', b'\xa1\x01\x18\x19'],
            'aes256/128_p': ['alg', 'AES-MAC256/128', 'PROTECTED', b'\xa1\x01\x18\x1a'],
            'aes128/64_u': ['alg', 'AES-MAC128/64', 'UNPROTECTED', {1: 14}],
            'aes256/64_u': ['alg', 'AES-MAC256/64', 'UNPROTECTED', {1: 15}],
            'aes128/128_u': ['alg', 'AES-MAC128/128', 'UNPROTECTED', {1: 25}],
            'aes256/128_u': ['alg', 'AES-MAC256/128', 'UNPROTECTED', {1: 26}],
            'kid_int_p': ['kid', 31868, 'PROTECTED', b'\xa1\x04\x19||'],
            'kid_string_p': ['kid', 'sleutel_id', 'PROTECTED', b'\xa1\x04Jsleutel_id'],
            'kid_int_u': ['kid', 31868, 'UNPROTECTED', {4: 31868}],
            'kid_string_u': ['kid', 'sleutel_id', 'UNPROTECTED', {4: b'sleutel_id'}],
            'iv_p': ['iv', unhexlify("a8c984a984b498489d489e68498f6847"), 'PROTECTED',
                     b'\xa1\x05P\xa8\xc9\x84\xa9\x84\xb4\x98H\x9dH\x9ehI\x8fhG'],
            'iv_u': ['iv', unhexlify("a8c984a984b498489d489e68498f6847"), 'UNPROTECTED',
                     {5: b'\xa8\xc9\x84\xa9\x84\xb4\x98H\x9dH\x9ehI\x8fhG'}]
        }

    header_find_params = \
        {
            'alg_in_p': ['alg', 'HS256', 'PROTECTED', "HS256"],
            'alg_in_u': ['alg', 'HS256', 'UNPROTECTED', "HS256"],
            'kid_in_p': ['kid', 31868, 'PROTECTED', 31868],
            'kid_in_u': ['kid', 31868, 'PROTECTED', 31868],
            'kid_str_in_p': ['kid', 'sleutel_id', 'PROTECTED', b'sleutel_id'],
            'kid_str_in_u': ['kid', 'sleutel_id', 'UNPROTECTED', b'sleutel_id'],
            'iv_in_p': ['iv', unhexlify("a8c984a984b498489d489e68498f6847"), 'PROTECTED',
                        unhexlify("a8c984a984b498489d489e68498f6847")],
            'iv_in_u': ['iv', unhexlify("a8c984a984b498489d489e68498f6847"), 'UNPROTECTED',
                        unhexlify("a8c984a984b498489d489e68498f6847")]
        }

    ex = unhexlify("11aa22bb33cc44dd55006699")
    key_1 = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
    cbor_1 = "D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA71" \
             "11E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B"

    key_2 = "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo"
    cbor_2 = "D28444A1013822A104445033383454546869732069732074686520636F6E74656E742E58605F150ABD1C7D25B32065A14E05D6C" \
             "B1F665D10769FF455EA9A2E0ADAB5DE63838DB257F0949C41E13330E110EBA7B912F34E1546FB1366A2568FAA91EC3E6C8D42F" \
             "4A67A0EDF731D88C9AEAD52258B2E2C4740EF614F02E9D91E9B7B59622A3C"

    test_cose_sign11_map = \
        {
            'msg1': [{'alg': 'ES256'}, {"kid": "11"}, ex, 'This is the content.', key_1, unhexlify(cbor_1)]
        }

    def test_header_encoding(self):
        for name_test, (a, b, c, d) in self.header_params.items():
            with self.subTest(name=name_test):
                sign1_msg = Sign1Message()
                sign1_msg.add_to_headers(a, b, c)
                if c == 'PROTECTED':
                    self.assertEqual(sign1_msg.protected_header, d, name_test)
                if c == 'UNPROTECTED':
                    self.assertEqual(sign1_msg.unprotected_header, d, name_test)

    def test_header_find(self):
        for name_test, (a, b, c, d) in self.header_find_params.items():
            with self.subTest(name=name_test):
                sign1_msg = Sign1Message()
                sign1_msg.add_to_headers(a, b, c)
                self.assertEqual(sign1_msg.find_in_headers(a), d, name_test)

    def test_cose_sign1_creation(self):
        for name_test, (a, b, x, c, d, e) in self.test_cose_sign11_map.items():
            with self.subTest(name=name_test):
                sign1_msg = Sign1Message()
                for k1 in a:
                    sign1_msg.add_to_headers(k1, a[k1], 'PROTECTED')
                for k2 in b:
                    sign1_msg.add_to_headers(k2, b[k2], 'UNPROTECTED')
                sign1_msg.external_aad = x
                sign1_msg.payload = c
                sign1_msg.key = d
                alg = sign1_msg.find_in_headers('alg')
                sign1_msg.signature = sign1_msg.compute_signature(alg)
                self.assertEqual(sign1_msg.encode(), e)


if __name__ == "__main__":
    unittest.main()
