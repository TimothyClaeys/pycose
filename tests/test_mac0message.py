import os
import unittest
from binascii import unhexlify, hexlify

from pycose import crypto
from pycose.cosemessage import CoseMessage
from pycose.mac0message import Mac0Message
from tests.testutilities import TestUtilities
from tests import TEST_ROOT


class CoseMAC0Encoder(unittest.TestCase):

    def test_encoding(self):
        util = TestUtilities()
        for test in util.get_next_test(os.path.join(TEST_ROOT, 'testcases', 'mac0-tests')):
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

                mac0_msg.key = crypto.base64decode(test_input['mac0']['recipients'][0]['key']['k'])

                self.assertEqual(mac0_msg._mac_structure, unhexlify(test_intermediates["ToMac_hex"]))
                self.assertEqual(mac0_msg.key, unhexlify(test_intermediates["CEK_hex"]))

                mac0_msg.compute_auth_tag(test_input['mac0']['alg'])

                if 'failures' in test_input:

                    failure = test_input['failures']
                    if 'ChangeCBORTag' in failure:
                        mac0_msg.cbor_tag = failure['ChangeCBORTag']
                        self.assertEqual(mac0_msg.encode(), unhexlify(test_output['cbor']))

                    elif 'ChangeTag' in failure:
                        decoded_msg = CoseMessage.decode(unhexlify(test_output['cbor']))
                        self.assertAlmostEqual(int(hexlify(mac0_msg.auth_tag), 16),
                                               int(hexlify(decoded_msg.auth_tag), 16), delta=1)

                    elif 'ChangeAttr' in failure:
                        if mac0_msg.protected_header:
                            mac0_msg.protected_header = failure["ChangeAttr"]
                        if mac0_msg.unprotected_header:
                            mac0_msg.unprotected_header = failure["ChangeAttr"]
                        self.assertEqual(mac0_msg.encode(), unhexlify(test_output['cbor']))

                    elif "AddProtected" in failure:
                        mac0_msg.add_to_headers(failure["AddProtected"], "PROTECTED")
                        self.assertEqual(mac0_msg.encode(), unhexlify(test_output['cbor']))

                    elif "RemoveProtected" in failure:
                        mac0_msg.remove_from_headers(failure["RemoveProtected"], "PROTECTED")
                        self.assertEqual(mac0_msg.encode(), unhexlify(test_output['cbor']))

                    elif "RemoveCBORTag" in failure:
                        self.assertEqual(hexlify(mac0_msg.encode())[2:], hexlify(unhexlify(test_output['cbor'])))

                    elif "ChangeProtected" in failure:
                        with self.assertRaises(TypeError):
                            mac0_msg.protected_header = failure["ChangeProtected"]

                    else:
                        raise Exception("Test case {} failed.".format(test_name))

                else:
                    self.assertEqual(mac0_msg.encode(), unhexlify(test_output['cbor']))


class CoseMAC0Decoder(unittest.TestCase):
    def test_encoding(self):
        util = TestUtilities()
        for test in util.get_next_test(os.path.join(TEST_ROOT, 'testcases', 'mac0-tests')):
            test_name = test['title']
            test_input = test['input']
            test_intermediates = test['intermediates']
            test_output = test['output']

            with self.subTest(name=test_name):
                if "failures" not in test_input:
                    decoded_msg = CoseMessage.decode(unhexlify(test_output['cbor']))
                    # check the decoded plaintext
                    self.assertEqual(decoded_msg.payload.decode('utf-8'), test_input["plaintext"])

                    # check the protected and unprotected headers
                    try:
                        if test_input["mac0"]["protected"]:
                            self.assertEqual(decoded_msg.protected_header, test_input["mac0"]["protected"])
                    except KeyError:
                        pass

                    try:
                        if test_input["mac0"]["unprotected"]:
                            self.assertEqual(decoded_msg.unprotected_header, test_input["mac0"]["unprotected"])
                    except KeyError:
                        pass

                    try:
                        if test_input["mac0"]["external"]:
                            self.assertNotEqual(decoded_msg._mac_structure, unhexlify(test_intermediates["ToMac_hex"]))
                            ex = test_input["mac0"]["external"]
                            extracted_tag = decoded_msg.auth_tag
                            decoded_msg.key = unhexlify(test_intermediates["CEK_hex"])
                            decoded_msg.compute_auth_tag(test_input["mac0"]["alg"])
                            self.assertNotEqual(extracted_tag, decoded_msg.auth_tag)
                            decoded_msg.external_aad = unhexlify(ex)
                            decoded_msg.compute_auth_tag(test_input["mac0"]["alg"])
                            self.assertEqual(extracted_tag, decoded_msg.auth_tag)
                        else:
                            self.assertEqual(decoded_msg._mac_structure, unhexlify(test_intermediates["ToMac_hex"]))
                    except KeyError:
                        pass

                    try:
                        if test_input["plaintext"]:
                            self.assertEqual(decoded_msg.payload, unhexlify(test_input["payload"]))
                    except KeyError:
                        pass

                    self.assertEqual(decoded_msg.encode(), unhexlify(test_output['cbor']))
                else:
                    print(test_name)



if __name__ == "__main__":
    unittest.main()
