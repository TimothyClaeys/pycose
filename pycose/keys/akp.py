from typing import Optional, Type, Union, List, TYPE_CHECKING

from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat, Encoding, NoEncryption
from cryptography.hazmat.primitives.asymmetric import mldsa

from pycose import utils
from pycose.exceptions import CoseInvalidKey, CoseIllegalKeyType, CoseIllegalKeyOps
from pycose.keys.cosekey import CoseKey, KpKty, KpAlg
from pycose.keys.keyops import SignOp, VerifyOp, DeriveBitsOp, DeriveKeyOp
from pycose.keys.keyparam import AKPKeyParam, AKPKpPub, AKPKpPriv
from pycose.keys.keytype import KtyAKP
from pycose.algorithms import CoseAlgorithm, MlDsa44, MlDsa65, MlDsa87

if TYPE_CHECKING:
    from pycose.keys.keyops import KEYOPS
    from pycose.keys.keyparam import KeyParam

PYCRYPTO_KEY_ALG = {
    mldsa.MLDSA44PrivateKey: MlDsa44,
    mldsa.MLDSA44PublicKey: MlDsa44,
    mldsa.MLDSA65PrivateKey: MlDsa65,
    mldsa.MLDSA65PublicKey: MlDsa65,
    mldsa.MLDSA87PrivateKey: MlDsa87,
    mldsa.MLDSA87PublicKey: MlDsa87,
}
PYCRYPTO_KEY_TYPES = tuple(PYCRYPTO_KEY_ALG.keys())

@CoseKey.record_kty(KtyAKP)
class AKPKey(CoseKey):

    @classmethod
    def from_dict(cls, cose_key: dict) -> 'AKPKey':
        """
        Returns an initialized COSE Key object of type AKPKey.

        :param cose_key: Dictionary containing COSE Key parameters and there values.

        :return: an initialized AKPKey key
        """
        _optional_params = {}

        # extract and remove items from dict, if not found return default value
        alg = CoseKey._extract_from_dict(cose_key, KpAlg, None)
        pub = CoseKey._extract_from_dict(cose_key, AKPKpPub)
        priv = CoseKey._extract_from_dict(cose_key, AKPKpPriv)

        _optional_params.update(cose_key)
        CoseKey._remove_from_dict(_optional_params, KpAlg)
        CoseKey._remove_from_dict(_optional_params, AKPKpPub)
        CoseKey._remove_from_dict(_optional_params, AKPKpPriv)

        return cls(alg=alg, pub=pub, priv=priv, optional_params=_optional_params, allow_unknown_key_attrs=True)

    @staticmethod
    def _from_cryptography_key(
        ext_key: Union[PYCRYPTO_KEY_TYPES],
        optional_params: Optional[dict] = None,
    ) -> 'AKPKey':
        """
        Returns an initialized COSE Key object of type AKPKey.
        :param ext_key: Python cryptography key.
        :return: an initialized AKP key
        """

        alg = None
        for ext_cls, use_alg in PYCRYPTO_KEY_ALG.items():
            if isinstance(ext_key, ext_cls):
                alg = use_alg
                break
        if alg is None:
            raise CoseIllegalKeyType(f'Unsupported key type {type(ext_key)}')

        if hasattr(ext_key, 'private_bytes'):
            priv_bytes = ext_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            pub_bytes = ext_key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
        else:
            priv_bytes = None
            pub_bytes = ext_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

        cose_key = {
            KpAlg: alg,
            AKPKpPub: pub_bytes,
        }
        if priv_bytes:
            cose_key[AKPKpPriv] = priv_bytes
        if optional_params:
            cose_key.update(optional_params)
        return AKPKey.from_dict(cose_key)

    @classmethod
    def _supports_cryptography_key_type(cls, ext_key) -> bool:
        return isinstance(ext_key, PYCRYPTO_KEY_TYPES)

    @staticmethod
    def _key_transform(key: Union[Type['AKPKeyParam'], Type['KeyParam'], str, int],
                       allow_unknown_attrs: bool = False):
        return AKPKeyParam.from_id(key, allow_unknown_attrs)

    def __init__(self,
                 alg: Union[Type['CoseAlgorithm'], str, int],
                 pub: bytes = b'',
                 priv: bytes = b'',
                 optional_params: Optional[dict] = None,
                 allow_unknown_key_attrs: bool = True):
        """
        Create an COSE AKP key.

        :param alg: An AKP elliptic curve.
        :param pub: Public value of the AKP key.
        :param priv: Private value of the AKP key.
        :param optional_params: A dictionary with optional key parameters.
        :param allow_unknown_key_attrs: Allow unknown key attributes (not registered at the IANA registry)
        """

        transformed_dict = {KpKty: KtyAKP}

        if optional_params is None:
            optional_params = {}

        for _key_attribute, _value in optional_params.items():
            # translate the key_attribute
            kp = AKPKeyParam.from_id(_key_attribute, allow_unknown_key_attrs)

            # parse the value of the key attribute if possible
            if hasattr(kp, 'value_parser') and hasattr(kp.value_parser, '__call__'):
                _value = kp.value_parser(_value)

            # store in new dict
            transformed_dict[kp] = _value

        # final check if key type is correct
        if transformed_dict.get(KpKty) != KtyAKP:
            raise CoseIllegalKeyType(f"Illegal key type in AKP COSE Key: {transformed_dict.get(KpKty)}")

        super(AKPKey, self).__init__(transformed_dict)

        if len(pub) == 0 and len(priv) == 0:
            raise CoseInvalidKey("Either the public values or the private value must be specified")

        if alg is not None:
            self.alg = alg
        else:
            raise CoseInvalidKey("COSE curve cannot be None")
        if pub != b'':
            self.pub = pub
        if priv != b'':
            self.priv = priv

    @property
    def pub(self) -> bytes:
        """
        Returns the mandatory :class:`~pycose.keys.keyparam.AKPKpPub` attribute of the COSE AKP Key object.
        """

        return self.store.get(AKPKpPub, b'')

    @pub.setter
    def pub(self, val: bytes):
        if type(val) is not bytes:
            raise TypeError("Public part must be of type 'bytes'")
        self.store[AKPKpPub] = val

    @property
    def priv(self) -> bytes:
        """
        Returns the mandatory :class:`~pycose.keys.keyparam.AKPKpPriv` attribute of the COSE AKP Key object.
        """

        return self.store.get(AKPKpPriv, b'')

    @priv.setter
    def priv(self, val: bytes):
        if type(val) is not bytes:
            raise TypeError("Private part must be of type 'bytes'")
        self.store[AKPKpPriv] = val

    @property
    def key_ops(self) -> List[Type['KEYOPS']]:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpKeyOps` key parameter """

        return CoseKey.key_ops.fget(self)

    @key_ops.setter
    def key_ops(self, new_key_ops: List[Union[Type['KEYOPS'], str, int]]) -> None:
        supported = {SignOp, VerifyOp, DeriveKeyOp, DeriveBitsOp}
        for ops in new_key_ops:
            if not self._supported_by_key_type(ops, supported):
                raise CoseIllegalKeyOps(f"Invalid COSE key operation {ops} for key type {AKPKey.__name__}")
            else:
                CoseKey.key_ops.fset(self, new_key_ops)

    @classmethod
    def generate_key(cls, alg: Union[Type['CoseAlgorithm'], str, int], optional_params: dict = None) -> 'AKPKey':
        """
        Generate a random AKPKey COSE key object.

        :param alg: Specify an algorithm.
        :param optional_params: Optional key attributes for the :class:`~pycose.keys.AKP.AKPKey` object, e.g., \
        :class:`~pycose.keys.keyparam.KpKid`.

        :returns: A COSE `AKPKey` key.
        """

        print('alg', alg)
        alg = CoseAlgorithm.from_id(alg)
        print('alg', alg)
        print('done')

        ext_key = alg.private_key_cls.generate()

        return cls._from_cryptography_key(ext_key, optional_params)

    def __delitem__(self, key: Union['KeyParam', str, int]):
        if self._key_transform(key) != KpKty and self._key_transform(key) != KpAlg:
            if self._key_transform(key) == AKPKpPriv and AKPKpPub not in self.store:
                pass
            elif self._key_transform(key) == AKPKpPub and AKPKpPriv not in self.store:
                pass
            else:
                return super(AKPKey, self).__delitem__(key)

        raise CoseInvalidKey(f"Deleting {key} attribute would lead to an invalid COSE AKP Key")

    def __repr__(self):
        _key = self._key_repr()

        if 'AKPKpD' in _key and len(_key['AKPKpD']) > 0:
            _key['AKPKpD'] = utils.truncate(_key['AKPKpD'])
        if 'AKPKpX' in _key and len(_key['AKPKpX']) > 0:
            _key['AKPKpX'] = utils.truncate(_key['AKPKpX'])
        if 'AKPKpY' in _key and len(_key['AKPKpY']) > 0:
            _key['AKPKpY'] = utils.truncate(_key['AKPKpY'])

        hdr = f'<COSE_Key(AKPKey): {_key}>'
        return hdr


AKP = AKPKey

if __name__ == '__main__':
    print(AKPKeyParam.get_registered_classes())
