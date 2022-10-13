from typing import Optional, Type, Union, List, TYPE_CHECKING

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from pycose import utils
from pycose.exceptions import CoseUnsupportedCurve, CoseInvalidKey, CoseIllegalKeyType, CoseIllegalKeyOps
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import SignOp, VerifyOp, DeriveKeyOp, DeriveBitsOp
from pycose.keys.keyparam import EC2KeyParam, EC2KpCurve, EC2KpX, EC2KpY, EC2KpD, KpKty, KeyParam
from pycose.keys.keytype import KtyEC2

if TYPE_CHECKING:
    from pycose.keys.keyops import KEYOPS
    from pycose.keys.curves import CoseCurve


@CoseKey.record_kty(KtyEC2)
class EC2Key(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'EC2Key':
        """
        Returns an initialized COSE Key object of type EC2Key.

        :param cose_key: Dict containing COSE Key parameters and their values.
        :return: an initialized EC2Key key
        """
        _optional_params = {}

        # extract and remove items from dict, if not found return default value
        x = CoseKey._extract_from_dict(cose_key, EC2KpX)
        y = CoseKey._extract_from_dict(cose_key, EC2KpY)
        d = CoseKey._extract_from_dict(cose_key, EC2KpD)
        curve = CoseKey._extract_from_dict(cose_key, EC2KpCurve, None)

        _optional_params.update(cose_key)
        CoseKey._remove_from_dict(_optional_params, EC2KpX)
        CoseKey._remove_from_dict(_optional_params, EC2KpY)
        CoseKey._remove_from_dict(_optional_params, EC2KpD)
        CoseKey._remove_from_dict(_optional_params, EC2KpCurve)

        return cls(crv=curve, x=x, y=y, d=d, optional_params=_optional_params, allow_unknown_key_attrs=True)

    @staticmethod
    def _key_transform(key: Union[Type['EC2KeyParam'], Type['KeyParam'], str, int], allow_unknown_attrs: bool = False):
        return EC2KeyParam.from_id(key, allow_unknown_attrs)

    def __init__(self,
                 crv: Union[Type['CoseCurve'], str, int],
                 x: bytes = b'',
                 y: bytes = b'',
                 d: bytes = b'',
                 optional_params: Optional[dict] = None,
                 allow_unknown_key_attrs: bool = True):
        """Initialize a COSE key from its components

        Not passing a `y` component is accepted; in this case, one (of the two)
        valid `y` will be found for the `x`. This is good enough for everything
        that only operates on the `x` of any derived outputs (in "compact"
        mode), as per RFC 6090 Section 4.2.
        """
        transformed_dict = {KpKty: KtyEC2}

        if optional_params is None:
            optional_params = {}

        for _key_attribute, _value in optional_params.items():
            # transform the key_attribute
            kp = EC2KeyParam.from_id(_key_attribute, allow_unknown_key_attrs)

            # parse the value of the key attribute if possible
            if hasattr(kp, 'value_parser') and hasattr(kp.value_parser, '__call__'):
                _value = kp.value_parser(_value)

            # store in new dict
            transformed_dict[kp] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtyEC2:
            raise CoseIllegalKeyType(f"Illegal key type in EC2 COSE Key: {transformed_dict.get(KpKty)}")

        super(EC2Key, self).__init__(transformed_dict)

        if crv is not None:
            self.crv = crv
        else:
            raise CoseInvalidKey("COSE curve cannot be None")

        if not x and not y and not d:
            raise CoseInvalidKey("Either the public values or the private value must be specified")

        if not d and not x:
            raise CoseInvalidKey("Missing public coordinate X")

        if d:
            public_nums = ec.derive_private_key(int.from_bytes(d, byteorder="big"),
                                                curve=self.crv.curve_obj(),
                                                backend=default_backend()).public_key().public_numbers()
            if x:
                assert x == public_nums.x.to_bytes(self.crv.size, 'big')
            else:
                x = public_nums.x.to_bytes(self.crv.size, 'big')

            if y:
                assert y == public_nums.y.to_bytes(self.crv.size, 'big')
            else:
                y = public_nums.y.to_bytes(self.crv.size, 'big')

        if x and not y:
            # try to derive y from x
            key = ec.EllipticCurvePublicKey.from_encoded_point(self.crv.curve_obj(),
                                                               # don't care which of the two possible Y values we get
                                                               b'\x03' +
                                                               x  # or [::-1]?
                                                               )
            # Just to check the endianness of the conversions -- if we get the
            # right X back out, then the X and Y are consistent, and anyway the
            # crypto backend will check whether the point is on the curve
            assert x == key.public_numbers().x.to_bytes(self.crv.size, 'big')
            y = key.public_numbers().y.to_bytes(self.crv.size, 'big')

        if x != b'':
            self.x = x
        if y != b'':
            self.y = y
        if d != b'':
            self.d = d

    @property
    def crv(self) -> Optional[Type['CoseCurve']]:
        """
        Returns the mandatory :class:`~pycose.keys.keyparam.EC2KpCurve` attribute of the COSE EC2 Key object.
        """

        if EC2KpCurve in self.store:
            return self.store[EC2KpCurve]
        else:
            raise CoseInvalidKey("EC2 COSE key must have the EC2KpCurve attribute")

    @crv.setter
    def crv(self, crv: Union[Type['CoseCurve'], int, str]):
        crv = EC2KpCurve.value_parser(crv)
        if crv.key_type != KtyEC2:
            raise CoseUnsupportedCurve(f"Invalid COSE curve {crv} for key type {EC2Key.__name__}")
        else:
            self.store[EC2KpCurve] = crv

    @property
    def x(self) -> bytes:
        """
        Returns the mandatory :class:`~pycose.keys.keyparam.EC2KpX` attribute of the COSE EC2 Key object.
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
        Returns the mandatory :class:`~pycose.keys.keyparam.EC2KpY` attribute of the COSE EC2 Key object.
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
        Returns the mandatory :class:`~pycose.keys.keyparam.EC2KpD` attribute of the COSE EC2 Key object.
        """

        return self.store.get(EC2KpD, b'')

    @d.setter
    def d(self, d: bytes):
        if type(d) is not bytes:
            raise TypeError("private key must be of type 'bytes'")
        self.store[EC2KpD] = d

    @property
    def key_ops(self) -> List[Type['KEYOPS']]:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpKeyOps` key parameter """

        return CoseKey.key_ops.fget(self)

    @key_ops.setter
    def key_ops(self, new_key_ops: List[Union[Type['KEYOPS'], str, int]]) -> None:
        supported = {SignOp, VerifyOp, DeriveKeyOp, DeriveBitsOp}
        for ops in new_key_ops:
            if not self._supported_by_key_type(ops, supported):
                raise CoseIllegalKeyOps(f"Invalid COSE key operation {ops} for key type {EC2Key.__name__}")
            else:
                CoseKey.key_ops.fset(self, new_key_ops)

    @classmethod
    def generate_key(cls, crv: Union[Type['CoseCurve'], str, int], optional_params: dict = None) -> 'EC2Key':
        """
        Generate a random EC2Key COSE key object.

        :param crv: Specify an :class:`~pycose.attributes.algorithms.CoseEllipticCurves`.
        :param optional_params: Optional key attributes for the :class:`~pycose.keys.ec2.EC2Key` object, e.g., \
        :class:`~pycose.keys.keyparam.KpAlg` or :class:`~pycose.keys.keyparam.KpKid`.

        :return: An COSE `EC2Key` key.
        """

        crv = EC2KpCurve.value_parser(crv)

        if crv.key_type != KtyEC2:
            raise CoseUnsupportedCurve(f'Unsupported COSE curve: {crv}')

        private_key = ec.generate_private_key(crv.curve_obj, backend=default_backend())
        d_value = private_key.private_numbers().private_value
        x_coor = private_key.public_key().public_numbers().x
        y_coor = private_key.public_key().public_numbers().y

        return EC2Key(crv=crv,
                      d=d_value.to_bytes(crv.size, "big"),
                      x=x_coor.to_bytes(crv.size, "big"),
                      y=y_coor.to_bytes(crv.size, "big"),
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


EC2 = EC2Key

if __name__ == '__main__':
    print(EC2KeyParam.get_registered_classes())
