import unittest

from pycose.attributes import CoseAttrs


class CoseAttrsTest(unittest.TestCase):
    test2_params = \
        {
            "test1": ['alg', "HS256/64", {1: 4}],
            "test2": ['alg', "HS256", {1: 5}],
            "test3": ['alg', "EdDSA", {1: -8}],
            "test4": ['alg', "AES-MAC128/64", {1: 14}],
            "test5": ['alg', "AES-MAC128/128", {1: 25}],
            "test6": ['alg', "A256GCM", {1: 3}]
        }

    def test1_reinstantiation(self):
        new_coseattr = CoseAttrs()
        new_coseattr['alg'] = "HS256/64"
        new_coseattr = CoseAttrs()
        # test for empty dictionary
        self.assertEqual(bool(new_coseattr), False)

    def test2_creation(self):
        for name_test, (a, b, c) in self.test2_params.items():
            with self.subTest(name=name_test):
                new_coseattr = CoseAttrs()
                new_coseattr[a] = b
                self.assertEqual(new_coseattr, c)


if __name__ == '__main__':
    unittest.main()
