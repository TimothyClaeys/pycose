from typing import Optional, Type, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1

from cose import utils
from cose.curves import P256, P521, P384, CoseCurve
from cose.exceptions import CoseIllegalCurve, CoseInvalidKey, CoseIllegalKeyType
from cose.keys.cosekey import CoseKey
from cose.keys.keyparam import EC2KeyParam, EC2KpCurve, EC2KpX, EC2KpY, EC2KpD, KpKty, KeyParam
from cose.keys.keytype import KtyEC2


@CoseKey.record_kty(KtyEC2)
class EC2Key(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'EC2Key':
        """
        Returns an initialized COSE Key object of type EC2Key.

        :param cose_key: Dict containing COSE Key parameters and there values.
        :return: an initialized EC2Key key
        """

        if EC2KpX in cose_key:
            x = cose_key[EC2KpX]
        elif EC2KpX.identifier in cose_key:
            x = cose_key[EC2KpX.identifier]
        elif EC2KpX.fullname in cose_key:
            x = cose_key[EC2KpX.fullname]
        else:
            x = b''

        if EC2KpY in cose_key:
            y = cose_key[EC2KpY]
        elif EC2KpY.identifier in cose_key:
            y = cose_key[EC2KpY.identifier]
        elif EC2KpY.fullname in cose_key:
            y = cose_key[EC2KpY.fullname]
        else:
            y = b''

        if EC2KpD in cose_key:
            d = cose_key[EC2KpD]
        elif EC2KpD.identifier in cose_key:
            d = cose_key[EC2KpD.identifier]
        elif EC2KpD.fullname in cose_key:
            d = cose_key[EC2KpD.fullname]
        else:
            d = b''

        if EC2KpCurve in cose_key:
            curve = cose_key[EC2KpCurve]
        elif EC2KpCurve.identifier in cose_key:
            curve = cose_key[EC2KpCurve.identifier]
        elif EC2KpCurve.fullname in cose_key:
            curve = cose_key[EC2KpCurve.fullname]
        else:
            raise CoseInvalidKey("COSE EC2 Key must have an EC2KpCurve attribute")

        return cls(crv=curve, x=x, y=y, d=d, optional_params=cose_key)

    @staticmethod
    def _key_transform(key: Union[Type['EC2KeyParam'], Type['KeyParam'], str, int]):
        return EC2KeyParam.from_id(key)

    def __init__(self, crv: Union[Type['CoseCurve'], str, int], x: bytes = b'', y: bytes = b'', d: bytes = b'',
                 optional_params: Optional[dict] = None):
        transformed_dict = {}

        if len(x) == 0 and len(y) == 0 and len(d) == 0:
            raise CoseInvalidKey("Either the public values or the private value must be specified")

        if (len(x) == 0 and len(y) != 0) or (len(x) != 0 and len(y) == 0):
            raise CoseInvalidKey("Missing public coordinate X/Y")

        new_dict = dict({KpKty: KtyEC2, EC2KpCurve: crv})

        if len(x) != 0 and len(y) != 0:
            new_dict.update({EC2KpX: x, EC2KpY: y})
        if len(d) != 0:
            new_dict.update({EC2KpD: d})

        if optional_params is not None:
            new_dict.update(optional_params)

        for _key_attribute, _value in new_dict.items():
            try:
                # translate the key_attribute
                kp = EC2KeyParam.from_id(_key_attribute)

                # parse the value of the key attribute if possible
                if hasattr(kp.value_parser, '__call__'):
                    _value = kp.value_parser(_value)

                # store in new dict
                transformed_dict[kp] = _value
            except ValueError:
                transformed_dict[_key_attribute] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtyEC2:
            raise CoseIllegalKeyType(f"Illegal key type in EC2 COSE Key: {transformed_dict.get(KpKty)}")

        super(EC2Key, self).__init__(transformed_dict)

    @property
    def crv(self) -> Optional[Type['CoseCurve']]:
        """
        Returns the mandatory :class:`~cose.keys.keyparam.EC2KpCurve` attribute of the COSE EC2 Key object.
        """

        if EC2KpCurve in self.store:
            return self.store[EC2KpCurve]
        else:
            raise CoseInvalidKey("EC2 COSE key must have the EC2KpCurve attribute")

    @crv.setter
    def crv(self, crv: Union[Type['CoseCurve'], int, str]):
        if crv not in [P256, P384, P521] \
                and crv not in [P256.identifier, P384.identifier, P521.identifier] \
                and crv not in [P256.fullname, P384.fullname, P521.fullname]:
            raise CoseIllegalCurve("Invalid COSE curve attribute")
        else:
            self.store[EC2KpCurve] = CoseCurve.from_id(crv)

    @property
    def x(self) -> bytes:
        """
        Returns the mandatory :class:`~cose.keys.keyparam.EC2KpX` attribute of the COSE EC2 Key object.
        """

        return self.store.get(EC2KpX, b'')

    @x.setter
    def x(self, x: bytes):
        if type(x) is not bytes:
            raise TypeError("public x coordinate must be of type 'bytes'")
        self.store[EC2KpX] = x

    @property
    def y(self) -> bytes:
        """
        Returns the mandatory :class:`~cose.keys.keyparam.EC2KpY` attribute of the COSE EC2 Key object.
        """

        return self.store.get(EC2KpY, b'')

    @y.setter
    def y(self, y: bytes):
        if type(y) is not bytes:
            raise TypeError("public y coordinate must be of type 'bytes'")
        self.store[EC2KpY] = y

    @property
    def d(self) -> bytes:
        """
        Returns the mandatory :class:`~cose.keys.keyparam.EC2KpD` attribute of the COSE EC2 Key object.
        """

        return self.store.get(EC2KpD, b'')

    @d.setter
    def d(self, d: bytes):
        if type(d) is not bytes:
            raise TypeError("private key must be of type 'bytes'")
        self.store[EC2KpD] = d

    @staticmethod
    def generate_key(curve: Union[Type['CoseCurve'], str, int], optional_params: dict = None) -> 'EC2Key':
        """
        Generate a random EC2Key COSE key object.

        :param curve: Specify an :class:`~cose.attributes.algorithms.CoseEllipticCurves`.
        :param optional_params: Optional key attributes for the :class:`~cose.keys.ec2.EC2Key` object, e.g., \
        :class:`~cose.keys.keyparam.KpAlg` or  :class:`~cose.keys.keyparam.KpKid`.

        :return: An COSE `EC2Key` key.
        """

        if type(curve) == str or type(curve) == int:
            curve = CoseCurve.from_id(curve)

        if curve == P256:
            curve_obj = SECP256R1()
        elif curve == P384:
            curve_obj = SECP384R1()
        elif curve == P521:
            curve_obj = SECP521R1()
        else:
            raise CoseIllegalCurve(f'Illegal COSE curve: {curve}')

        private_key = ec.generate_private_key(curve_obj, backend=default_backend())
        d_value = private_key.private_numbers().private_value
        x_coor = private_key.public_key().public_numbers().x
        y_coor = private_key.public_key().public_numbers().y

        return EC2Key(
            crv=curve,
            d=d_value.to_bytes((d_value.bit_length() + 7) // 8, byteorder="big"),
            x=x_coor.to_bytes((x_coor.bit_length() + 7) // 8, byteorder="big"),
            y=y_coor.to_bytes((y_coor.bit_length() + 7) // 8, byteorder="big"),
            optional_params=optional_params)

    def __delitem__(self, key):
        if self._key_transform(key) != KpKty and self._key_transform(key) != EC2KpCurve:
            if self._key_transform(key) == EC2KpD and (EC2KpY not in self.store or EC2KpX not in self.store):
                pass
            elif self._key_transform(key) == EC2KpX and EC2KpD not in self.store:
                pass
            elif (self._key_transform(key) == EC2KpX or self._key_transform(key) == EC2KpY) and EC2KpD in self.store:
                super(EC2Key, self).__delitem__(EC2KpX)
                super(EC2Key, self).__delitem__(EC2KpY)
                return
            else:
                return super(EC2Key, self).__delitem__(key)

        raise CoseInvalidKey(f"Deleting {key} attribute would lead to an invalid COSE EC2 Key")

    def __repr__(self):
        _key = self._key_repr()

        if 'EC2KpD' in _key and len(_key['EC2KpD']) > 0:
            _key['EC2KpD'] = utils.truncate(_key['EC2KpD'])
        if 'EC2KpX' in _key and len(_key['EC2KpX']) > 0:
            _key['EC2KpX'] = utils.truncate(_key['EC2KpX'])
        if 'EC2KpY' in _key and len(_key['EC2KpY']) > 0:
            _key['EC2KpY'] = utils.truncate(_key['EC2KpY'])

        hdr = f'<COSE_Key(EC2Key): {_key}>'
        return hdr


EC2KpCurve.value_parser = CoseCurve.from_id

EC2 = EC2Key

if __name__ == '__main__':
    print(EC2KeyParam.get_registered_classes())
