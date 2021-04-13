import os
from typing import Optional, Union, Type

from cose import utils
from cose.exceptions import CoseInvalidKey, CoseIllegalKeyType
from cose.keys.cosekey import CoseKey
from cose.keys.keyparam import KpKty, SymmetricKeyParam, SymKpK, KeyParam
from cose.keys.keytype import KtySymmetric


@CoseKey.record_kty(KtySymmetric)
class SymmetricKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'SymmetricKey':
        """
        Returns an initialized COSE Key object of type SymmetricKey.

        :param cose_key: Dict containing COSE Key parameters and their values.

        :return: an initialized COSE SymmetricKey object
        """

        if SymKpK in cose_key:
            key_bytes = cose_key[SymKpK]
        elif SymKpK.identifier in cose_key:
            key_bytes = cose_key[SymKpK.identifier]
        elif SymKpK.fullname in cose_key:
            key_bytes = cose_key[SymKpK.fullname]
        else:
            raise CoseInvalidKey("COSE Symmetric Key must have an SymKpK attribute")

        return cls(key=key_bytes, optional_params=cose_key)

    @staticmethod
    def _key_transform(key: Union[Type['SymmetricKeyParam'], Type['KeyParam'], str, int]):
        return SymmetricKeyParam.from_id(key)

    def __init__(self, key: bytes, optional_params: Optional[dict] = None):
        transformed_dict = {}

        if len(key) not in [16, 24, 32]:
            raise CoseInvalidKey("Key length should be either 16, 24, or 32 bytes")

        new_dict = dict({KpKty: KtySymmetric, SymKpK: key})

        if optional_params is not None:
            new_dict.update(optional_params)

        for _key_attribute, _value in new_dict.items():
            try:
                # translate the key_attribute
                kp = SymmetricKeyParam.from_id(_key_attribute)

                # parse the value of the key attribute if possible
                if hasattr(kp.value_parser, '__call__'):
                    _value = kp.value_parser(_value)

                # store in new dict
                transformed_dict[kp] = _value
            except ValueError:
                transformed_dict[_key_attribute] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtySymmetric:
            raise CoseIllegalKeyType(f"Illegal key type in Symmetric COSE Key: {transformed_dict.get(KpKty)}")

        super(SymmetricKey, self).__init__(transformed_dict)

    def __delitem__(self, key):
        if self._key_transform(key) != KpKty and self._key_transform(key) != SymKpK:
            super().__delitem__(key)
        else:
            raise CoseInvalidKey(f"Deleting {key} attribute would lead to an invalide COSE Symmetric Key")

    @property
    def k(self) -> bytes:
        """ Returns the mandatory :class:`~cose.keys.keyparam.SymKpK` attribute of the COSE Symmetric Key object. """
        if SymKpK in self.store:
            return self.store[SymKpK]
        else:
            raise CoseInvalidKey("Symmetric COSE key must have the SymKpK attribute")

    @k.setter
    def k(self, k: bytes):

        if type(k) is not bytes:
            raise ValueError("symmetric key must be of type 'bytes'")
        self.store[SymKpK] = k

    @staticmethod
    def generate_key(key_len: int, optional_params: dict = None) -> 'SymmetricKey':
        """
        Generate a random Symmetric COSE key object.

        :param key_len: Symmetric key length in bytes, must be of size 16, 24 or 32.
        :param optional_params: Optional key attributes for the :class:`~cose.keys.symmetric.SymmetricKey` object, \
        e.g., :class:`~cose.keys.keyparam.KpAlg` or  :class:`~cose.keys.keyparam.KpKid`.

        :raises ValueError: For invalid key lengths.

        :returns: A COSE_key of type SymmetricKey.
        """

        if key_len not in [16, 24, 32]:
            raise ValueError("key_len must be of size 16, 24 or 32")

        return SymmetricKey(key=os.urandom(key_len), optional_params=optional_params)

    def __repr__(self):
        _key = self._key_repr()

        if 'SymKpK' in _key and len(_key['SymKpK']) > 0:
            _key['SymKpK'] = utils.truncate(_key['SymKpK'])

        hdr = f'<COSE_Key(Symmetric): {_key}>'

        return hdr


SK = SymmetricKey

if __name__ == '__main__':
    print(SymmetricKeyParam.get_registered_classes())
