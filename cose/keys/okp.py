from typing import Optional, Type, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat, Encoding

from cose import utils
from cose.curves import X448, X25519, Ed25519, Ed448, CoseCurve
from cose.exceptions import CoseIllegalCurve, CoseInvalidKey, CoseIllegalKeyType
from cose.keys.cosekey import CoseKey, KpKty
from cose.keys.keyparam import OKPKeyParam, OKPKpCurve, OKPKpX, OKPKpD, KeyParam
from cose.keys.keytype import KtyOKP


@CoseKey.record_kty(KtyOKP)
class OKPKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'OKPKey':
        """
        Returns an initialized COSE Key object of type OKPKey.

        :param cose_key: Dictionary containing COSE Key parameters and there values.

        :return: an initialized OKPKey key
        """

        if OKPKpX in cose_key:
            x = cose_key[OKPKpX]
        elif OKPKpX.identifier in cose_key:
            x = cose_key[OKPKpX.identifier]
        elif OKPKpX.fullname in cose_key:
            x = cose_key[OKPKpX.fullname]
        else:
            x = b''

        if OKPKpD in cose_key:
            d = cose_key[OKPKpD]
        elif OKPKpD.identifier in cose_key:
            d = cose_key[OKPKpD.identifier]
        elif OKPKpD.fullname in cose_key:
            d = cose_key[OKPKpD.fullname]
        else:
            d = b''

        if OKPKpCurve in cose_key:
            curve = cose_key[OKPKpCurve]
        elif OKPKpCurve.identifier in cose_key:
            curve = cose_key[OKPKpCurve.identifier]
        elif OKPKpCurve.fullname in cose_key:
            curve = cose_key[OKPKpCurve.fullname]
        else:
            raise CoseInvalidKey("COSE OKP Key must have an OKPKpCurve attribute")

        return cls(crv=curve, x=x, d=d, optional_params=cose_key)

    @staticmethod
    def _key_transform(key: Union[Type['OKPKeyParam'], Type['KeyParam'], str, int]):
        return OKPKeyParam.from_id(key)

    def __init__(self, crv: Union[Type['CoseCurve'], str, int], x: bytes = b'', d: bytes = b'',
                 optional_params: Optional[dict] = None):
        """
        Create an COSE OKP key.

        :param crv: An OKP elliptic curve.
        :param x: Public value of the OKP key.
        :param d: Private value of the OKP key.
        :param optional_params: A dictionary with optional key parameters.
        """

        transformed_dict = {}

        if len(x) == 0 and len(d) == 0:
            raise CoseInvalidKey("Either the public values or the private value must be specified")

        new_dict = dict({KpKty: KtyOKP, OKPKpCurve: crv})

        if len(x) != 0:
            new_dict.update({OKPKpX: x})
        if len(d) != 0:
            new_dict.update({OKPKpD: d})

        if optional_params is not None:
            new_dict.update(optional_params)

        for _key_attribute, _value in new_dict.items():
            try:
                # translate the key_attribute
                kp = OKPKeyParam.from_id(_key_attribute)

                # parse the value of the key attribute if possible
                if hasattr(kp, 'value_parser') and hasattr(kp.value_parser, '__call__'):
                    _value = kp.value_parser(_value)

                # store in new dict
                transformed_dict[kp] = _value
            except ValueError:
                transformed_dict[_key_attribute] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtyOKP:
            raise CoseIllegalKeyType(f"Illegal key type in OKP COSE Key: {transformed_dict.get(KpKty)}")

        super(OKPKey, self).__init__(transformed_dict)

    @property
    def crv(self) -> Optional[Type['CoseCurve']]:
        """
        Returns the mandatory :class:`~cose.keys.keyparam.OKPKpCurve` attribute of the COSE OKP Key object.
        """

        if OKPKpCurve in self.store:
            return self.store[OKPKpCurve]
        else:
            raise CoseInvalidKey("OKP COSE key must have the OKP KpCurve attribute")

    @crv.setter
    def crv(self, crv: Union[Type['CoseCurve'], int, str]):
        if crv not in [X25519, X448, Ed25519, Ed448] \
                and crv not in [X25519.identifier, X448.identifier, Ed25519.identifier, Ed448.identifier] \
                and crv not in [X25519.fullname, X448.fullname, Ed25519.fullname, Ed448.identifier]:
            raise CoseIllegalCurve("Invalid COSE curve attribute")
        else:
            self.store[OKPKpCurve] = CoseCurve.from_id(crv)

    @property
    def x(self) -> bytes:
        """
        Returns the mandatory :class:`~cose.keys.keyparam.OKPKpX` attribute of the COSE OKP Key object.
        """

        return self.store.get(OKPKpX, b'')

    @x.setter
    def x(self, x: bytes):
        if type(x) is not bytes:
            raise TypeError("public x coordinate must be of type 'bytes'")
        self.store[OKPKpX] = x

    @property
    def d(self) -> bytes:
        """
        Returns the mandatory :class:`~cose.keys.keyparam.OKPKpD` attribute of the COSE OKP Key object.
        """

        return self.store.get(OKPKpD, b'')

    @d.setter
    def d(self, d: bytes):
        if type(d) is not bytes:
            raise TypeError("private key must be of type 'bytes'")
        self.store[OKPKpD] = d

    @staticmethod
    def generate_key(curve: Union[Type['CoseCurve'], str, int], optional_params: dict = None) -> 'OKPKey':
        """
        Generate a random OKPKey COSE key object.

        :param curve: Specify an elliptic curve.
        :param optional_params: Optional key attributes for the :class:`~cose.keys.okp.OKPKey` object, e.g., \
        :class:`~cose.keys.keyparam.KpAlg` or  :class:`~cose.keys.keyparam.KpKid`.

        :returns: A COSE `OKPKey` key.
        """

        if type(curve) == str or type(curve) == int:
            curve = CoseCurve.from_id(curve)

        if curve == X25519:
            private_key = X25519PrivateKey.generate()
        elif curve == Ed25519:
            private_key = Ed25519PrivateKey.generate()
        elif curve == Ed448:
            private_key = Ed448PrivateKey.generate()
        elif curve == X448:
            private_key = X448PrivateKey.generate()
        else:
            raise CoseIllegalCurve(f"Curve must be of type {X25519}, {X448}, {Ed25519}, or {Ed448}")

        encoding = Encoding(serialization.Encoding.Raw)
        private_format = PrivateFormat(serialization.PrivateFormat.Raw)
        public_format = PublicFormat(serialization.PublicFormat.Raw)
        encryption = serialization.NoEncryption()

        return OKPKey(
            crv=curve,
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


OKPKpCurve.value_parser = CoseCurve.from_id

OKP = OKPKey

if __name__ == '__main__':
    print(OKPKeyParam.get_registered_classes())
