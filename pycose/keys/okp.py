from typing import Optional, Type, Union, List, TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat, Encoding

from pycose import utils
from pycose.exceptions import CoseUnsupportedCurve, CoseInvalidKey, CoseIllegalKeyType, CoseIllegalKeyOps
from pycose.keys.cosekey import CoseKey, KpKty
from pycose.keys.keyops import KEYOPS, SignOp, VerifyOp, DeriveBitsOp, DeriveKeyOp
from pycose.keys.keyparam import OKPKeyParam, OKPKpCurve, OKPKpX, OKPKpD, KeyParam
from pycose.keys.keytype import KtyOKP

if TYPE_CHECKING:
    from pycose.keys.keyops import KEYOPS
    from pycose.keys.curves import CoseCurve


@CoseKey.record_kty(KtyOKP)
class OKPKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'OKPKey':
        """
        Returns an initialized COSE Key object of type OKPKey.

        :param cose_key: Dictionary containing COSE Key parameters and there values.

        :return: an initialized OKPKey key
        """
        _optional_params = {}

        # extract and remove items from dict, if not found return default value
        x = CoseKey._extract_from_dict(cose_key, OKPKpX)
        d = CoseKey._extract_from_dict(cose_key, OKPKpD)
        curve = CoseKey._extract_from_dict(cose_key, OKPKpCurve, None)

        _optional_params.update(cose_key)
        CoseKey._remove_from_dict(_optional_params, OKPKpX)
        CoseKey._remove_from_dict(_optional_params, OKPKpD)
        CoseKey._remove_from_dict(_optional_params, OKPKpCurve)

        return cls(crv=curve, x=x, d=d, optional_params=_optional_params, allow_unknown_key_attrs=True)

    @staticmethod
    def _key_transform(key: Union[Type['OKPKeyParam'], Type['KeyParam'], str, int],
                       allow_unknown_attrs: bool = False):
        return OKPKeyParam.from_id(key, allow_unknown_attrs)

    def __init__(self,
                 crv: Union[Type['CoseCurve'], str, int],
                 x: bytes = b'',
                 d: bytes = b'',
                 optional_params: Optional[dict] = None,
                 allow_unknown_key_attrs: bool = True):
        """
        Create an COSE OKP key.

        :param crv: An OKP elliptic curve.
        :param x: Public value of the OKP key.
        :param d: Private value of the OKP key.
        :param optional_params: A dictionary with optional key parameters.
        :param allow_unknown_key_attrs: Allow unknown key attributes (not registered at the IANA registry)
        """

        transformed_dict = {KpKty: KtyOKP}

        if optional_params is None:
            optional_params = {}

        for _key_attribute, _value in optional_params.items():
            # translate the key_attribute
            kp = OKPKeyParam.from_id(_key_attribute, allow_unknown_key_attrs)

            # parse the value of the key attribute if possible
            if hasattr(kp, 'value_parser') and hasattr(kp.value_parser, '__call__'):
                _value = kp.value_parser(_value)

            # store in new dict
            transformed_dict[kp] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtyOKP:
            raise CoseIllegalKeyType(f"Illegal key type in OKP COSE Key: {transformed_dict.get(KpKty)}")

        super(OKPKey, self).__init__(transformed_dict)

        if len(x) == 0 and len(d) == 0:
            raise CoseInvalidKey("Either the public values or the private value must be specified")

        if crv is not None:
            self.crv = crv
        else:
            raise CoseInvalidKey("COSE curve cannot be None")
        if x != b'':
            self.x = x
        if d != b'':
            self.d = d

    @property
    def crv(self) -> Optional[Type['CoseCurve']]:
        """
        Returns the mandatory :class:`~pycose.keys.keyparam.OKPKpCurve` attribute of the COSE OKP Key object.
        """

        if OKPKpCurve in self.store:
            return self.store[OKPKpCurve]
        else:
            raise CoseInvalidKey("OKP COSE key must have the OKP KpCurve attribute")

    @crv.setter
    def crv(self, crv: Union[Type['CoseCurve'], int, str]):
        crv = OKPKpCurve.value_parser(crv)
        if crv.key_type != KtyOKP:
            raise CoseUnsupportedCurve(f"Invalid COSE curve {crv} for key type {OKPKey.__name__}")
        else:
            self.store[OKPKpCurve] = crv

    @property
    def x(self) -> bytes:
        """
        Returns the mandatory :class:`~pycose.keys.keyparam.OKPKpX` attribute of the COSE OKP Key object.
        """

        return self.store.get(OKPKpX, b'')

    @x.setter
    def x(self, x: bytes):
        if type(x) is not bytes:
            raise TypeError("Public x-coordinate must be of type 'bytes'")
        self.store[OKPKpX] = x

    @property
    def d(self) -> bytes:
        """
        Returns the mandatory :class:`~pycose.keys.keyparam.OKPKpD` attribute of the COSE OKP Key object.
        """

        return self.store.get(OKPKpD, b'')

    @d.setter
    def d(self, d: bytes):
        if type(d) is not bytes:
            raise TypeError("Private key must be of type 'bytes'")
        self.store[OKPKpD] = d

    @property
    def key_ops(self) -> List[Type['KEYOPS']]:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpKeyOps` key parameter """

        return CoseKey.key_ops.fget(self)

    @key_ops.setter
    def key_ops(self, new_key_ops: List[Union[Type['KEYOPS'], str, int]]) -> None:
        supported = {SignOp, VerifyOp, DeriveKeyOp, DeriveBitsOp}
        for ops in new_key_ops:
            if not self._supported_by_key_type(ops, supported):
                raise CoseIllegalKeyOps(f"Invalid COSE key operation {ops} for key type {OKPKey.__name__}")
            else:
                CoseKey.key_ops.fset(self, new_key_ops)

    @classmethod
    def generate_key(cls, crv: Union[Type['CoseCurve'], str, int], optional_params: dict = None) -> 'OKPKey':
        """
        Generate a random OKPKey COSE key object.

        :param crv: Specify an elliptic curve.
        :param optional_params: Optional key attributes for the :class:`~pycose.keys.okp.OKPKey` object, e.g., \
        :class:`~pycose.keys.keyparam.KpAlg` or  :class:`~pycose.keys.keyparam.KpKid`.

        :returns: A COSE `OKPKey` key.
        """

        crv = OKPKpCurve.value_parser(crv)

        if crv.key_type != KtyOKP:
            raise CoseUnsupportedCurve(f'Unsupported COSE curve: {crv}')

        encoding = Encoding(serialization.Encoding.Raw)
        private_format = PrivateFormat(serialization.PrivateFormat.Raw)
        public_format = PublicFormat(serialization.PublicFormat.Raw)
        encryption = serialization.NoEncryption()

        private_key = crv.curve_obj.generate()

        return OKPKey(
            crv=crv,
            x=private_key.public_key().public_bytes(encoding, public_format),
            d=private_key.private_bytes(encoding, private_format, encryption),
            optional_params=optional_params)

    def __delitem__(self, key: Union['KeyParam', str, int]):
        if self._key_transform(key) != KpKty and self._key_transform(key) != OKPKpCurve:
            if self._key_transform(key) == OKPKpD and OKPKpX not in self.store:
                pass
            if self._key_transform(key) == OKPKpX and OKPKpD not in self.store:
                pass
            else:
                return super(OKPKey, self).__delitem__(key)

        raise CoseInvalidKey(f"Deleting {key} attribute would lead to an invalid COSE OKP Key")

    def __repr__(self):
        _key = self._key_repr()

        if 'OKPKpD' in _key and len(_key['OKPKpD']) > 0:
            _key['OKPKpD'] = utils.truncate(_key['OKPKpD'])
        if 'OKPKpX' in _key and len(_key['OKPKpX']) > 0:
            _key['OKPKpX'] = utils.truncate(_key['OKPKpX'])
        if 'OKPKpY' in _key and len(_key['OKPKpY']) > 0:
            _key['OKPKpY'] = utils.truncate(_key['OKPKpY'])

        hdr = f'<COSE_Key(OKPKey): {_key}>'
        return hdr


OKP = OKPKey

if __name__ == '__main__':
    print(OKPKeyParam.get_registered_classes())
