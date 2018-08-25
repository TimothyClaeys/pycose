import os
import unittest
from binascii import unhexlify, hexlify

from pycose import crypto
from pycose.cosemessage import CoseMessage
from pycose.enc0message import Enc0Message
from tests import TEST_ROOT
from tests.testutilities import TestUtilities


class CoseEnc0Encoder(unittest.TestCase):

    def test_encoding(self):
        util = TestUtilities()
        for test in util.get_next_test(os.path.join(TEST_ROOT, 'testcases', 'encrypted-tests')):
            test_name = test['title']
            test_input = test['input']
            test_intermediates = test['intermediates']
            test_output = test['output']
            enc0_msg = Enc0Message()

            with self.subTest(name=test_name):

                enc0_msg.payload = test_input['plaintext']

                try:
                    enc0_msg.protected_header = test_input['encrypted']['protected']
                    alg = test_input['encrypted']['protected']['alg']
                except KeyError:
                    pass

                try:
                    enc0_msg.unprotected_header = test_input['encrypted']['unprotected']
                    alg = test_input['encrypted']['protected']['alg']
                except KeyError:
                    pass

                # add nonce to the unprotected header
                enc0_msg.add_to_headers({'iv': unhexlify(test_input['rng_stream'][0])}, "UNPROTECTED")

                try:
                    enc0_msg.external_aad = unhexlify(test_input['encrypted']['external'])
                except KeyError:
                    pass

                enc0_msg.key = crypto.base64decode(test_input['encrypted']['recipients'][0]['key']['k'])

                self.assertEqual(enc0_msg._enc_structure, unhexlify(test_intermediates["AAD_hex"]))
                self.assertEqual(enc0_msg.key, unhexlify(test_intermediates["CEK_hex"]))

                enc0_msg.encrypt(alg, nonce=unhexlify(test_input['rng_stream'][0]))

                if 'failures' in test_input:

                    failure = test_input['failures']
                    if 'ChangeCBORTag' in failure:
                        enc0_msg.cbor_tag = failure['ChangeCBORTag']
                        self.assertEqual(enc0_msg.encode(), unhexlify(test_output['cbor']))

                    elif 'ChangeTag' in failure:
                        decoded_msg = CoseMessage.decode(unhexlify(test_output['cbor']))
                        self.assertAlmostEqual(int(hexlify(enc0_msg.payload), 16),
                                               int(hexlify(decoded_msg.payload), 16), delta=1)

                    elif 'ChangeAttr' in failure:
                        if enc0_msg.find_in_headers(enc0_msg.protected_header, 'alg'):
                            enc0_msg.protected_header = failure["ChangeAttr"]
                        elif enc0_msg.find_in_headers(enc0_msg.unprotected_header, 'alg'):
                            enc0_msg.unprotected_header = failure["ChangeAttr"]
                        self.assertEqual(enc0_msg.encode(), unhexlify(test_output['cbor']))

                    elif "AddProtected" in failure:
                        enc0_msg.add_to_headers(failure["AddProtected"], "PROTECTED")
                        self.assertEqual(enc0_msg.encode(), unhexlify(test_output['cbor']))

                    elif "RemoveProtected" in failure:
                        enc0_msg.remove_from_headers(failure["RemoveProtected"], "PROTECTED")
                        self.assertEqual(enc0_msg.encode(), unhexlify(test_output['cbor']))

                    elif "RemoveCBORTag" in failure:
                        self.assertEqual(hexlify(enc0_msg.encode())[2:], hexlify(unhexlify(test_output['cbor'])))

                    elif "ChangeProtected" in failure:
                        with self.assertRaises(TypeError):
                            enc0_msg.protected_header = failure["ChangeProtected"]

                    else:
                        raise Exception("Test case {} failed.".format(test_name))

                else:
                    self.assertEqual(enc0_msg.encode(), unhexlify(test_output['cbor']))


if __name__ == "__main__":
    unittest.main()
