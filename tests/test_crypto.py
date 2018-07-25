import unittest
from binascii import unhexlify

from pycose import crypto
from pycose.exceptions import *

class CryptoTests(unittest.TestCase):
    """tests for the crypto functions"""

    key_1 = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
    to_sign_1 = "85695369676E617475726543A1030043A101264054546869732069732074686520636F6E74656E742E"
    sig_1 = 'D71C05DB52C9CE7F1BF5AAC01334BBEACAC1D86A2303E6EEAA89266F45C01ED602CA649EAF790D8BC99D2458457CA6A872061940E7AFBE48E289DFAC146AE258'

    key_2 = "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo"
    to_sign_2 = "85695369676E61747572654044A10138224054546869732069732074686520636F6E74656E742E"
    sig_2 = "230DF24B9F31DD2D7D1B9C33CE59073FC21E02BB63DC55847626B5B7F43905D59ACC186890BC1FE8B6D12E61B0373FFBA131ECC6C21958CDFF28AD77E0C32F9A0C6CA247135F538496228B2BE5557E7DBD7280DB24B46B68C0772D1BAEF09DE5"

    signatures_map = \
        {
            'ecdsa256': [key_1, unhexlify(to_sign_1), 'ES256', 'P-256', unhexlify(sig_1)],
            # 'ecdsa384': [key_2, unhexlify(to_sign_2), 'ES384', 'P-384', unhexlify(sig_2)]
        }

    def test_signature_schemes(self):
        for name_test, (a, b, c, d, e) in self.signatures_map.items():
            with self.subTest(name=name_test):
                self.assertEqual(crypto.ec_sign_wrapper(a, b, c, d), e)

    def test_generate_keys(self):
        key = crypto.generate_crypto_keys()
        data = "This message will be signed.".encode('utf-8')
        signature = crypto.ec_sign_wrapper(key, data)
        self.assertTrue(crypto.ec_verify_wrapper(key, data, signature))

    def test_unsupported_ciphers(self):
        key = unhexlify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188")
        test_string = b"ThisIsATestString"
        with self.assertRaises(CoseUnsupportedHMAC):
            crypto.hmac_wrapper(key, test_string, "HS257")


if __name__ == "__main__":
    unittest.main()
