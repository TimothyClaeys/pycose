import abc
from copy import deepcopy
from typing import Optional, Any, Dict, Type, Tuple, TypeVar

import cbor2

from pycose import utils
from pycose.algorithms import CoseAlgorithm
from pycose.exceptions import CoseException
from pycose.headers import CoseHeaderAttribute, Algorithm
from pycose.keys.cosekey import CoseKey
from pycose.keys.cosekey import KpKeyOps

CBOR = bytes


class CoseBase(metaclass=abc.ABCMeta):
    """ Basic COSE information buckets. """

    @classmethod
    def from_cose_obj(cls: Type['CB'], cose_obj: list, allow_unknown_attributes: bool) -> 'CB':
        phdr_encoded = cose_obj.pop(0)
        uhdr = cose_obj.pop(0)

        return cls(phdr_encoded=phdr_encoded, uhdr=uhdr, allow_unknown_attributes=allow_unknown_attributes)

    def __init__(self, phdr: Optional[dict] = None, uhdr: Optional[dict] = None, payload: Optional[bytes] = None, phdr_encoded: Optional[bytes] = None, *args, **kwargs):
        if phdr is not None and phdr_encoded is not None:
            raise ValueError("Cannot have both phdr and phdr_encoded")
        
        if phdr_encoded is not None:
            if phdr_encoded == b"":
                phdr = {}
            else:
                phdr = cbor2.loads(phdr_encoded)
        elif phdr is None:
            phdr = {}

        if uhdr is None:
            uhdr = {}

        if type(phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")

        if type(uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")

        self._local_attrs = {}

        self.alg_tstr_encoding = kwargs.get("alg_tstr_encoding", False)

        self._phdr_encoded = phdr_encoded
        self._phdr = CoseBase._parse_header(phdr, kwargs.get("allow_unknown_attributes", True))
        self._uhdr = CoseBase._parse_header(uhdr, kwargs.get("allow_unknown_attributes", True))

        # can be plaintext or ciphertext
        if payload is not None and type(payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = payload

    def get_attr(self, attribute: Type[CoseHeaderAttribute], default: Any = None) -> Optional[Any]:
        """
        Fetches an header attribute from the COSE header buckets.

        :param attribute: A header parameter to fetch from the buckets.
        :param default: A default return value in case the attribute was not found

        :raise CoseException: When the same attribute is found in both the protected and unprotected header.
        :returns: If found returns a header attribute else 'None' or the default value
        """

        p_attr = self._phdr.get(attribute, default)
        u_attr = self._uhdr.get(attribute, default)

        if p_attr is not None and u_attr is not None:
            raise CoseException("MALFORMED: different values for the same header parameters in the header buckets")

        if p_attr is not None:
            return p_attr
        else:
            return u_attr

    @property
    def phdr(self) -> dict:
        return self._phdr

    @phdr.setter
    def phdr(self, new_phdr: dict) -> None:
        if type(new_phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr = deepcopy(new_phdr)
        self._phdr_encoded = None

    @property
    def uhdr(self) -> dict:
        return self._uhdr

    @uhdr.setter
    def uhdr(self, new_uhdr: dict) -> None:
        if type(new_uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr = deepcopy(new_uhdr)

    def phdr_update(self, phdr_params: dict) -> None:
        if type(phdr_params) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr.update(phdr_params)
        self._phdr_encoded = None

    def uhdr_update(self, uhdr_params: dict) -> None:
        if type(uhdr_params) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr.update(uhdr_params)

    @property
    def local_attrs(self):
        return self._local_attrs

    @local_attrs.setter
    def local_attrs(self, attributes: Dict['CoseHeaderAttribute', Any]):
        for k, v in attributes.items():
            self._local_attrs[k] = v

    @property
    def phdr_encoded(self) -> CBOR:
        """
        Encode the protected header.

        :returns: Returns the encoded protected header.
        """

        if self._phdr_encoded is not None:
            return self._phdr_encoded
        # TODO: check if not double header parameters in header buckets
        if len(self._phdr):
            return cbor2.dumps(self._phdr, default=self._custom_cbor_encoder)
        else:
            return b''

    @property
    def uhdr_encoded(self) -> dict:
        """
        Encode the unprotected header.

        :returns: Returns the encoded unprotected header.
        """

        # TODO: check if not double header parameters in header buckets
        return self._uhdr

    def _custom_cbor_encoder(self, encoder, cose_attribute: Type['CoseHeaderAttribute']):
        if isinstance(cose_attribute, CoseKey):
            new_dict = dict(cose_attribute)
            if KpKeyOps in new_dict and not len(new_dict[KpKeyOps]):
                del new_dict[KpKeyOps]
            encoder.encode(new_dict)
        elif issubclass(cose_attribute, CoseAlgorithm) and self.alg_tstr_encoding:
            encoder.encode(cose_attribute.fullname)
        else:
            encoder.encode(cose_attribute.identifier)

    @classmethod
    def _parse_header(cls, hdr, allow_unknown_attributes: bool) -> dict:
        decoded_hdr = {}
        for k, v in hdr.items():
            attr = CoseHeaderAttribute.from_id(k, allow_unknown_attributes)

            if hasattr(attr, 'value_parser'):
                decoded_hdr[attr] = attr.value_parser(v)
            else:
                decoded_hdr[attr] = v

        return decoded_hdr

    def _hdr_repr(self) -> Tuple[dict, dict]:
        phdr = {(k.__name__ if hasattr(k, '__name__') else k): (
            self._phdr[k].__name__ if hasattr(self._phdr[k], '__name__') else self._phdr[k]) for k in self._phdr}

        uhdr = {(k.__name__ if hasattr(k, '__name__') else k): (
            self._uhdr[k].__name__ if hasattr(self._uhdr[k], '__name__') else self._uhdr[k]) for k in self._uhdr}

        if 'IV' in phdr and len(phdr['IV']) > 0:
            phdr['IV'] = utils.truncate(phdr['IV'])

        if 'IV' in uhdr and len(uhdr['IV']) > 0:
            uhdr['IV'] = utils.truncate(uhdr['IV'])

        if 'PARTIAL_IV' in phdr and len(phdr['PARTIAL_IV']) > 0:
            phdr['PARTIAL_IV'] = utils.truncate(phdr['PARTIAL_IV'])

        if 'PARTIAL_IV' in uhdr and len(uhdr['PARTIAL_IV']) > 0:
            uhdr['PARTIAL_IV'] = utils.truncate(uhdr['PARTIAL_IV'])

        return phdr, uhdr

CB = TypeVar('CB', bound=CoseBase)
