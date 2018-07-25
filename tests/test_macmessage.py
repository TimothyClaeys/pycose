import unittest
from binascii import unhexlify

from pycose.cosemessage import CoseMessage
from pycose.macmessage import MacMessage
from pycose.attributes import CoseAttrs


class CoseMACTests(unittest.TestCase):
    """tests for cose_mac message types"""

    recipients_params = \
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

    recipient_find_params = \
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

    def test_recipient_params(self):
        for name_test, (a, b, c, d) in self.recipients_params.items():
            with self.subTest(name=name_test):
                mac_msg = MacMessage()
                mac_msg.add_to_recipients(1, a, b, c)
                if c == 'PROTECTED':
                    self.assertEqual(mac_msg.recipients[0][0], d, name_test)
                if c == 'UNPROTECTED':
                    self.assertEqual(mac_msg.recipients[0][1], d, name_test)

    def test_recipient_find(self):
        for name_test, (a, b, c, d) in self.recipient_find_params.items():
            with self.subTest(name=name_test):
                mac_msg = MacMessage()
                mac_msg.add_to_recipients(1, a, b, c)
                self.assertEqual(mac_msg.find_in_recipients(a), d, name_test)

    cbor_1 = "D8618540A1010554546869732069732074686520636F6E74656E742E582060CFE7D9C733A758E198FF758A381E43B3CAF986" \
             "7AEBAEF224CA8F11FFD3AC7A818340A20125044A6F75722D73656372657440"
    key_1 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"
    external = unhexlify("11aa22bb33cc44dd55006699")

    cbor_2 = "D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD6" \
             "3484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440"
    key_2 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"

    cbor_3 = "D8618543A10106A054546869732069732074686520636F6E74656E742E5830B3097F70009A11507409598A83E15BBBBF" \
             "1982DCE28E5AB6D5A6AFF6897BD24BB8B7479622C9401B24090D458206D587818340A2012504467365632D343840"
    key_3 = "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C42718800112233778899AA2122232425262728"

    test_cose_mac1_map = \
        {
            # name test : p_header, u_header, ex_aed, payload,
            'msg1': [{}, {'alg': 'HS256'}, external, 'This is the content.', {}, {"alg": "direct", "kid": "our-secret"},
                     unhexlify(key_1), unhexlify(cbor_1)],
            'msg2': [{'alg': 'HS256'}, {}, '', 'This is the content.', {}, {"alg": "direct", "kid": "our-secret"},
                     unhexlify(key_2), unhexlify(cbor_2)],
            'msg3': [{'alg': 'HS384'}, {}, '', 'This is the content.', {}, {"alg": "direct", "kid": "sec-48"},
                     unhexlify(key_3), unhexlify(cbor_3)],
            'msg4': [{'alg': 'HS384'}, {}, '', 'This is the content.', {}, {"alg": "direct", "kid": "sec-48"},
                     unhexlify(key_3), unhexlify(cbor_3)],

        }

    test_cose_mac2_map = \
        {
            'msg1': [{'alg': 'HS256'}, {}, '', 'This is the content.', {}, {"alg": "direct", "kid": "our-secret"},
                     unhexlify(key_2), unhexlify(cbor_2)],
            'msg2': [{'alg': 'HS384'}, {}, '', 'This is the content.', {}, {"alg": "direct", "kid": "sec-48"},
                     unhexlify(key_3), unhexlify(cbor_3)],
            'msg3': [{'alg': 'HS384'}, {}, '', 'This is the content.', {}, {"alg": "direct", "kid": "sec-48"},
                     unhexlify(key_3), unhexlify(cbor_3)],

        }

    def test_cose_mac1_creation(self):
        for name_test, (a, b, x, c, d, e, f, g) in self.test_cose_mac1_map.items():
            mac_msg = MacMessage()
            with self.subTest(name=name_test):
                mac_msg.protected_header = a
                mac_msg.unprotected_header = b
                mac_msg.external_aad = x
                mac_msg.payload = c
                for k3 in d:
                    mac_msg.add_to_recipients(1, k3, d[k3], 'PROTECTED')
                for k4 in e:
                    mac_msg.add_to_recipients(1, k4, e[k4], 'UNPROTECTED')
                mac_msg.key = f
                try:
                    alg = mac_msg.find_in_headers('alg')
                except KeyError as err:
                    alg = mac_msg.find_in_recipients('alg')
                mac_msg.compute_auth_tag(alg)
                self.assertEqual(mac_msg.encode(), g)

    def test_received_mac0_msg(self):
        for name_test, (a, b, x, c, d, e, f, g) in self.test_cose_mac2_map.items():
            with self.subTest(name=name_test):
                cose_msg = CoseMessage.decode(g)
                cose_msg.key = f
                try:
                    alg = cose_msg.find_in_headers('alg')
                except KeyError as err:
                    alg = cose_msg.find_in_recipients('alg')

                print(cose_msg.verify_auth_tag(alg))


if __name__ == "__main__":
    unittest.main()
