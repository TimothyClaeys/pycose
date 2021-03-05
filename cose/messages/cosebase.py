import abc
from copy import deepcopy
from typing import Optional, Any, Dict, Type, Tuple

import cbor2

from cose.keys.cosekey import CoseKey
from cose.headers import CoseHeaderAttribute
from cose.exceptions import CoseException
from cose.keys.cosekey import KpKeyOps

CBOR = bytes


class CoseBase(metaclass=abc.ABCMeta):
    """ Basic COSE information buckets. """

    @classmethod
    def from_cose_obj(cls, cose_obj: list, *args, **kwargs):
        try:
            phdr = cls._parse_header(cbor2.loads(cose_obj.pop(0)))
        except (ValueError, EOFError):
            phdr = {}

        try:
            uhdr = cls._parse_header(cose_obj.pop(0))
        except ValueError:
            uhdr = {}

        return cls(phdr, uhdr)

    def __init__(self, phdr: Optional[dict] = None, uhdr: Optional[dict] = None, payload: bytes = b''):
        if phdr is None:
            phdr = {}

        if uhdr is None:
            uhdr = {}

        if type(phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")

        if type(uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")

        self._local_attrs = {}
        self._phdr = deepcopy(phdr)
        self._uhdr = deepcopy(uhdr)

        # can be plaintext or ciphertext
        if type(payload) is not bytes:
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

    @classmethod
    def _custom_cbor_encoder(cls, encoder, cose_attribute: 'CoseHeaderAttribute'):
        if isinstance(cose_attribute, CoseKey):
            new_dict = dict(cose_attribute)
            if KpKeyOps in new_dict and not len(new_dict[KpKeyOps]):
                del new_dict[KpKeyOps]
            encoder.encode(new_dict)
        else:
            encoder.encode(cose_attribute.identifier)

    @classmethod
    def _parse_header(cls, hdr) -> dict:
        decoded_hdr = {}
        for k, v in hdr.items():
            attr = CoseHeaderAttribute.from_id(k)
            decoded_hdr[attr] = attr.value_parser(v)

        return decoded_hdr

    def _hdr_repr(self) -> Tuple[dict, dict]:
        phdr = {(k.__name__ if hasattr(k, '__name__') else k): (
            self._phdr[k].__name__ if hasattr(self._phdr[k], '__name__') else self._phdr[k]) for k in self._phdr}

        uhdr = {(k.__name__ if hasattr(k, '__name__') else k): (
            self._uhdr[k].__name__ if hasattr(self._uhdr[k], '__name__') else self._uhdr[k]) for k in self._uhdr}

        return phdr, uhdr
