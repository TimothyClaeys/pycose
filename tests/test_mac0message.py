import unittest
from binascii import unhexlify

from cosemessage import CoseMessage
from mac0message import Mac0Message


class CoseMAC0Tests(unittest.TestCase):
    """tests for cose_mac0 message types"""

    header_params = \
        {
            'hash256/64_p' :['alg', 'HS256/64', 'PROTECTED', b'\xa1\x01\x04'],
            'hash256_p' :['alg', 'HS256', 'PROTECTED', b'\xa1\x01\x05'],
            'hash384_p' :['alg', 'HS384', 'PROTECTED', b'\xa1\x01\x06'],
            'hash512_p' :['alg', 'HS512', 'PROTECTED', b'\xa1\x01\x07'],
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

    cbor_1 = "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A" \
             "848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58"
    key_1 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"

    cbor_2 = "D18443A10106A054546869732069732074686520636F6E74656E742E583099" \
             "8D26C6459AAEECF44ED20CE00C8CCEDF0A1F3D22A92FC05DB08C5AEB1CB594CAAF5A5C5E2E9D01CCE7E77A93AA8C62"
    key_2 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C42718800112233778899AA2122232425262728"

    cbor_3 = "D18443A10107A054546869732069732074686520636F6E74656E742E58404A555BF971F7C1891D9DDF304A" \
             "1A132E2D6F817449474D813E6D04D65962BED8BBA70C17E1F5308FA39962959A4B9B8D7DA8E6D849B209DCD3E98CC0F11EDDF2"
    key_3 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C4271880" \
            "0112233778899AA2122232425262728AABBCCDDEEFFA5A6A7A8A9A0B1B2B3B4"

    cbor_4 = "D18443A10104A054546869732069732074686520636F6E74656E742E4811F9E357975FB849"
    key_4 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"

    cbor_5 = "D18440A1010554546869732069732074686520636F6E74656E742E58200" \
             "FECAEC59BB46CC8A488AACA4B205E322DD52696B75A45768D3C302DD4BAE2F7"
    ex = unhexlify("ff00ee11dd22cc33bb44aa559966")
    key_5 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"

    test_cose_mac1_map = \
        {
            'msg1' : [{'alg': 'HS256'},{},'','This is the content.', unhexlify(key_1), unhexlify(cbor_1)],
            'msg2' : [{'alg': 'HS384'},{},'','This is the content.', unhexlify(key_2), unhexlify(cbor_2)],
            'msg3': [{'alg': 'HS512'}, {},'', 'This is the content.', unhexlify(key_3), unhexlify(cbor_3)],
            'msg4': [{'alg': 'HS256/64'}, {},'', 'This is the content.', unhexlify(key_4), unhexlify(cbor_4)],
            'msg5': [{}, {'alg': 'HS256'}, ex, 'This is the content.', unhexlify(key_5), unhexlify(cbor_5)]
        }

    test_cose_mac2_map = \
        {
            'rcv1' : [{'alg': 'HS256'},{},'','This is the content.', unhexlify(key_1), unhexlify(cbor_1)],
            'rcv2' : [{'alg': 'HS384'},{},'','This is the content.', unhexlify(key_2), unhexlify(cbor_2)],
            'rcv3': [{'alg': 'HS512'}, {},'', 'This is the content.', unhexlify(key_3), unhexlify(cbor_3)],
            'rcv4': [{'alg': 'HS256/64'}, {},'', 'This is the content.', unhexlify(key_4), unhexlify(cbor_4)]
        }

    def test_header_encoding(self):
        for name_test, (a, b, c, d) in self.header_params.items():
            with self.subTest(name=name_test):
                mac0_msg = Mac0Message()
                mac0_msg.add_to_headers(a,b,c)
                if c == 'PROTECTED':
                    self.assertEqual(mac0_msg.protected_header, d, name_test)
                if c == 'UNPROTECTED':
                    self.assertEqual(mac0_msg.unprotected_header, d, name_test)

    def test_header_find(self):
        for name_test, (a, b, c, d) in self.header_find_params.items():
            with self.subTest(name=name_test):
                mac0_msg = Mac0Message()
                mac0_msg.add_to_headers(a,b,c)
                self.assertEqual(mac0_msg.find_in_headers(a), d, name_test)

    def test_cose_mac1_creation(self):
        for name_test, (a, b, x, c, d, e) in self.test_cose_mac1_map.items():
            with self.subTest(name=name_test):
                mac0_msg = Mac0Message()
                for k1 in a:
                    mac0_msg.add_to_headers(k1, a[k1], 'PROTECTED')
                for k2 in b:
                    mac0_msg.add_to_headers(k2, b[k2], 'UNPROTECTED')
                mac0_msg.external_aad = x
                mac0_msg.payload = c
                mac0_msg.key = d
                alg = mac0_msg.find_in_headers('alg')
                mac0_msg.compute_auth_tag(alg)
                self.assertEqual(mac0_msg.encode(), e)

    def test_received_mac0_msg(self):
        for name_test, (a, b, x, c, d, e) in self.test_cose_mac2_map.items():
            with self.subTest(name=name_test):
                cose_msg = CoseMessage.decode(e)
                cose_msg.key = d
                alg = cose_msg.find_in_headers('alg')
                print(cose_msg.verify_auth_tag(alg))

if __name__ == "__main__":
    unittest.main()
