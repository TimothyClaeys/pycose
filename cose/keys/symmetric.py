import os
from typing import Optional

from cose.keys.cosekey import CoseKey
from cose.keys.keyparam import KpKty, SymmetricKeyParam, SymKpK, KpKeyOps
from cose.keys.keytype import KtySymmetric


@CoseKey.record_kty(KtySymmetric)
class SymmetricKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'SymmetricKey':
        """
        Returns an initialized COSE Key object of type EC2Key.

        :param cose_key: Dict containing COSE Key parameters and there values.
        :return: an initialized EC2Key key
        """

        return cls(cose_key)

    def __init__(self, key: Optional[dict] = None, **kwargs):
        transformed_dict = {}
        if key is None:
            key = {}

        new_dict = dict(key, **kwargs)
        new_dict[KpKty] = KtySymmetric

        for k, v in new_dict.items():
            try:
                kp = SymmetricKeyParam.from_id(k)
                v = v if kp.value_parser is None else kp.value_parser(v)
                transformed_dict[kp] = v
            except ValueError:
                transformed_dict[k] = v

        super(SymmetricKey, self).__init__(transformed_dict)

    @property
    def k(self) -> bytes:
        return self.store.get(SymKpK, b'')

    @k.setter
    def k(self, k: bytes):
        if type(k) is not bytes:
            raise ValueError("symmetric key must be of type 'bytes'")
        self.store[SymKpK] = k

    @staticmethod
    def generate_key(key_len) -> 'SymmetricKey':
        """
        Generate a random Symmetric COSE key object.

        :param key_len: Symmetric key length in bytes, must be of size 16, 24 or 32.
        :raises ValueError: For invalid key lengths.
        :raises CoseIllegalKeyOps: When the key operation is not allowed on this key type.
        :returns: A COSE_key of type SymmetricKey.
        """

        if key_len not in [16, 24, 32]:
            raise ValueError("key_len must be of size 16, 24 or 32")

        return SymmetricKey(k=os.urandom(key_len))

    @property
    def is_valid_key(self):
        return len(self.k) == 16 or len(self.k) == 24 or len(self.k) == 32

    def __repr__(self):

        hdr = f'<COSE_Key(Symmetric): {self._key_repr()}>'
        return hdr


SK = SymmetricKey

if __name__ == '__main__':
    print(SymmetricKeyParam.get_registered_classes())
