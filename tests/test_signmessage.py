import unittest
from binascii import unhexlify

from pycose.cosemessage import CoseMessage
from pycose.signmessage import SignMessage


class CoseSignTests(unittest.TestCase):
    """tests for cose_mac message types"""

    signature_struct_params = \
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

    signature_struct_find_params = \
        {
            'alg_in_p' : ['alg', 'HS256', 'PROTECTED', "HS256"],
            'alg_in_u': ['alg', 'HS256', 'UNPROTECTED', "HS256"],
            'kid_in_p' : ['kid', 31868, 'PROTECTED', 31868],
            'kid_in_u': ['kid', 31868, 'PROTECTED', 31868],
            'kid_str_in_p': ['kid', 'sleutel_id', 'PROTECTED', b'sleutel_id'],
            'kid_str_in_u': ['kid', 'sleutel_id', 'UNPROTECTED', b'sleutel_id'],
            'iv_in_p': ['iv', unhexlify("a8c984a984b498489d489e68498f6847"), 'PROTECTED',
                        unhexlify("a8c984a984b498489d489e68498f6847")],
            'iv_in_u': ['iv', unhexlify("a8c984a984b498489d489e68498f6847"), 'UNPROTECTED',
                     unhexlify("a8c984a984b498489d489e68498f6847")]
        }

    cbor_1 = "D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840CBB8DAD9BEAFB890E1A4141" \
             "24D8BFBC26BEDF2A94FCB5A882432BFF6D63E15F574EEB2AB51D83FA2CBF62672EBF4C7D993B0F4C2447647D831BA57CCA86B930A"
    key_1 = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
    external = unhexlify("11aa22bb33cc44dd55006699")

    test_cose_sign_map = \
        {
            'msg1': [{}, {}, external, 'This is the content.', {"alg":"ES256"}, {"kid":"11"},
                     key_1, unhexlify(cbor_1)],
        }

    cbor_2 = "D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E5207" \
             "7C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"
    key_2 = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"

    test_cose_sign2_map = \
        {
            'msg1': [{}, {},'', 'This is the content.', {"alg":"ES256"}, {"kid":"11"},
                     key_2, unhexlify(cbor_2)],
        }

    def test_signers_params(self):
        for name_test, (a, b, c, d) in self.signature_struct_params.items():
            with self.subTest(name=name_test):
                sign_msg = SignMessage()
                sign_msg.add_to_signers(1, a, b, c)
                if c == 'PROTECTED':
                    self.assertEqual(sign_msg.signers[0][0], d, name_test)
                if c == 'UNPROTECTED':
                    self.assertEqual(sign_msg.signers[0][1], d, name_test)

    def test_signers_find(self):
        for name_test, (a, b, c, d) in self.signature_struct_find_params.items():
            with self.subTest(name=name_test):
                sign_msg = SignMessage()
                sign_msg.add_to_signers(1, a, b, c)
                self.assertEqual(sign_msg.find_in_signers(a), d, name_test)

    def test_cose_sign_creation(self):
        for name_test, (a, b, x, c, d, e, f, g) in self.test_cose_sign_map.items():
            with self.subTest(name=name_test):
                sign_msg = SignMessage()
                for k1 in a:
                    sign_msg.add_to_headers(k1, a[k1], 'PROTECTED')
                for k2 in b:
                    sign_msg.add_to_headers(k2, b[k2], 'UNPROTECTED')
                sign_msg.external_aad = x
                sign_msg.payload = c
                for k3 in d:
                    sign_msg.add_to_signers(1, k3, d[k3],'PROTECTED')
                for k4 in e:
                    sign_msg.add_to_signers(1, k4, e[k4], 'UNPROTECTED')
                sign_msg.key = f
                try:
                    alg = sign_msg.find_in_headers('alg')
                except KeyError as err:
                    alg = sign_msg.find_in_signers('alg')

                sign_msg.add_signature_to_signers(1, sign_msg.compute_signature(alg))

                self.assertEqual(sign_msg.encode(), g)

    def test_received_cose_msg(self):
        for name_test, (a, b, x, c, d, e, f, g) in self.test_cose_sign2_map.items():
            with self.subTest(name=name_test):
                cose_msg = CoseMessage.decode(g)
                cose_msg.key = f
                try:
                    alg = cose_msg.find_in_headers('alg')
                except KeyError as err:
                    alg = cose_msg.find_in_signers('alg')

                self.assertTrue(cose_msg.verify_signature(alg, signer=1))


if __name__ == "main":
    unittest.main()