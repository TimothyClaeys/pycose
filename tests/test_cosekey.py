from binascii import unhexlify

import pytest

from pycose.cosekey import EC2, EllipticCurveKeys, CoseKey, KTY


@pytest.mark.parametrize("crv, x, y, expected",
                         [
                             (EllipticCurveKeys.P_256,
                              CoseKey.base64decode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
                              CoseKey.base64decode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
                              {1: 2, -1: 1,
                               -2: unhexlify(b'98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'),
                               -3: unhexlify(b'F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB')}),
                             (EllipticCurveKeys.P_521,
                              CoseKey.base64decode(
                                  "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"),
                              CoseKey.base64decode(
                                  "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
                              {1: 2, -1: 3,
                               -2: unhexlify(
                                   b'000E2CE3AA90FB69E4C648BABA21A8B616ACF6D9F2AF7699888DD8FF9A6DF164B059F6842AD27DD24F1893FAC8D5C03283CF60211F9D17138662DC8F1547C289C2A5'),
                               -3: unhexlify(
                                   b'0084D56A168242745AA99EFDA9D58D4439EEC0A6AA434918BC549F57F31F38B2C0A80FF0B8754367F315D1BE1D805BB95DA3880E01035E760E92CA8517D313F591EE')}),
                             (EllipticCurveKeys.P_256,
                              CoseKey.base64decode("7cvYCcdU22WCwW1tZXR8iuzJLWGcd46xfxO1XJs-SPU"),
                              CoseKey.base64decode("DzhJXgz9RI6TseNmwEfLoNVns8UmvONsPzQDop2dKoo"),
                              {-1: 1,
                               -2: unhexlify(b'EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F5'),
                               -3: unhexlify(b'0F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A'),
                               1: 2}
                              )
                         ])
def test_cosekey_create(crv, x, y, expected):
    key = EC2(crv=crv, x=x, y=y)
    assert sorted(key.encode('x', 'y', 'crv')) == sorted(expected)


@pytest.mark.parametrize('encoded_key_obj, expected',
                         [
                             ({-1: 1,
                               -2: unhexlify(b'EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F5'),
                               -3: unhexlify(b'0F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A'),
                               1: 2},
                              {CoseKey.Common.KTY: KTY.EC2,
                               EC2.EC2Prm.CRV: EllipticCurveKeys.P_256,
                               EC2.EC2Prm.X: unhexlify(
                                   b'edcbd809c754db6582c16d6d65747c8aecc92d619c778eb17f13b55c9b3e48f5'),
                               EC2.EC2Prm.Y: unhexlify(
                                   b'0f38495e0cfd448e93b1e366c047cba0d567b3c526bce36c3f3403a29d9d2a8a')}
                              )
                         ])
def test_cosekey_decode(encoded_key_obj, expected):
    key = CoseKey.decode(encoded_key_obj)
    assert key == expected
