import unittest
from binascii import unhexlify, hexlify

from pycose import crypto
from pycose.mac0message import Mac0Message
from tests.testutilities import TestUtilities


class CoseMAC0Encoder(unittest.TestCase):

    def test_encoding(self):
        util = TestUtilities()
        for test in util.get_next_test("../testcases/mac0-tests"):
            test_name = test['title']
            test_input = test['input']
            test_intermediates = test['intermediates']
            test_output = test['output']
            mac0_msg = Mac0Message()

            with self.subTest(name=test_name):

                mac0_msg.payload = test_input['plaintext']

                try:
                    mac0_msg.protected_header = test_input['mac0']['protected']
                except KeyError:
                    pass

                try:
                    mac0_msg.unprotected_header = test_input['mac0']['unprotected']
                except KeyError:
                    pass

                try:
                    mac0_msg.external_aad = unhexlify(test_input['mac0']['external'])
                except KeyError:
                    pass

                mac0_msg.key = crypto.base64urldecode(test_input['mac0']['recipients'][0]['key']['k'])

                self.assertEqual(mac0_msg._mac_structure, unhexlify(test_intermediates["ToMac_hex"]))
                self.assertEqual(mac0_msg.key, unhexlify(test_intermediates["CEK_hex"]))

                mac0_msg.compute_auth_tag(test_input['mac0']['alg'])

                if 'failures' in test_input:
                    self.assertNotEqual(mac0_msg.encode(), unhexlify(test_output['cbor']))
                    """
                    failure = test_input['failures']
                    if 'ChangeProtected' in failure:
                        mac0_msg.encoded_protected_header = unhexlify(test_input['failures']['ChangeProtected'])
                        TestUtilities.find_failures(str(mac0_msg), test_output['cbor_diag'])
                    """

                else:
                    self.assertEqual(mac0_msg.encode(), unhexlify(test_output['cbor']))


if __name__ == "__main__":
    unittest.main()
