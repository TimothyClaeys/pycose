import os
from typing import Optional, Union, Type, List, TYPE_CHECKING

from pycose import utils
from pycose.exceptions import CoseInvalidKey, CoseIllegalKeyType, CoseIllegalKeyOps
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import MacCreateOp, MacVerifyOp, EncryptOp, DecryptOp, UnwrapOp, WrapOp
from pycose.keys.keyparam import KpKty, SymmetricKeyParam, SymKpK, KeyParam
from pycose.keys.keytype import KtySymmetric

if TYPE_CHECKING:
    from pycose.keys.keyops import KEYOPS


@CoseKey.record_kty(KtySymmetric)
class SymmetricKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'SymmetricKey':
        """
        Returns an initialized COSE Key object of type SymmetricKey.

        :param cose_key: Dict containing COSE Key parameters and their values.

        :return: an initialized COSE SymmetricKey object
        """
        _optional_params = {}

        k = CoseKey._extract_from_dict(cose_key, SymKpK)

        _optional_params.update(cose_key)
        CoseKey._remove_from_dict(_optional_params, SymKpK)

        return cls(k=k, optional_params=_optional_params, allow_unknown_key_attrs=True)

    @staticmethod
    def _key_transform(key: Union[Type['SymmetricKeyParam'], Type['KeyParam'], str, int],
                       allow_unknown_attrs: bool = False):
        return SymmetricKeyParam.from_id(key, allow_unknown_attrs)

    def __init__(self, k: bytes, optional_params: Optional[dict] = None, allow_unknown_key_attrs: bool = True):
        transformed_dict = {KpKty: KtySymmetric}

        if optional_params is None:
            optional_params = {}

        for _key_attribute, _value in optional_params.items():
            # translate the key_attribute
            kp = SymmetricKeyParam.from_id(_key_attribute, allow_unknown_key_attrs)

            # parse the value of the key attribute if possible
            if hasattr(kp, 'value_parser') and hasattr(kp.value_parser, '__call__'):
                _value = kp.value_parser(_value)

            # store in new dict
            transformed_dict[kp] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtySymmetric:
            raise CoseIllegalKeyType(f"Illegal key type in Symmetric COSE Key: {transformed_dict.get(KpKty)}")

        super(SymmetricKey, self).__init__(transformed_dict)

        if k != b'':
            self.k = k
        else:
            raise CoseInvalidKey("SymKpK parameter cannot be None")

    def __delitem__(self, key):
        if self._key_transform(key) != KpKty and self._key_transform(key) != SymKpK:
            super().__delitem__(key)
        else:
            raise CoseInvalidKey(f"Deleting {key} attribute would lead to an invalide COSE Symmetric Key")

    @property
    def k(self) -> bytes:
        """ Returns the mandatory :class:`~pycose.keys.keyparam.SymKpK` attribute of the COSE Symmetric Key object. """
        if SymKpK in self.store:
            return self.store[SymKpK]
        else:
            raise CoseInvalidKey("Symmetric COSE key must have the SymKpK attribute")

    @k.setter
    def k(self, k: bytes):
        if type(k) is not bytes:
            raise ValueError("SymKpK parameter must be of type 'bytes'")
        if len(k) not in [16, 24, 32]:
            raise CoseInvalidKey("Key length should be either 16, 24, or 32 bytes")
        self.store[SymKpK] = k

    @property
    def key_ops(self) -> List[Type['KEYOPS']]:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpKeyOps` key parameter """

        return CoseKey.key_ops.fget(self)

    @key_ops.setter
    def key_ops(self, new_key_ops: List[Type['KEYOPS']]) -> None:
        supported = {MacCreateOp, MacVerifyOp, EncryptOp, DecryptOp, UnwrapOp, WrapOp}
        for ops in new_key_ops:
            if not self._supported_by_key_type(ops, supported):
                raise CoseIllegalKeyOps(f"Invalid COSE key operation {ops} for key type {SymmetricKey.__name__}")
            else:
                CoseKey.key_ops.fset(self, new_key_ops)

    @classmethod
    def generate_key(cls, key_len: int, optional_params: dict = None) -> 'SymmetricKey':
        """
        Generate a random Symmetric COSE key object.

        :param key_len: Symmetric key length in bytes, must be of size 16, 24 or 32.
        :param optional_params: Optional key attributes for the :class:`~pycose.keys.symmetric.SymmetricKey` object, \
        e.g., :class:`~pycose.keys.keyparam.KpAlg` or  :class:`~pycose.keys.keyparam.KpKid`.

        :raises ValueError: For invalid key lengths.

        :returns: A COSE_key of type SymmetricKey.
        """

        if key_len not in [16, 24, 32]:
            raise ValueError("key_len must be of size 16, 24 or 32")

        return SymmetricKey(k=os.urandom(key_len), optional_params=optional_params)

    def __repr__(self):
        _key = self._key_repr()

        if 'SymKpK' in _key and len(_key['SymKpK']) > 0:
            _key['SymKpK'] = utils.truncate(_key['SymKpK'])

        hdr = f'<COSE_Key(Symmetric): {_key}>'

        return hdr


SK = SymmetricKey

if __name__ == '__main__':
    print(SymmetricKeyParam.get_registered_classes())
