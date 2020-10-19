import abc
from typing import Optional

import cbor2
from cose import attributes as attr


class CoseBase(metaclass=abc.ABCMeta):
    """ Basic COSE information buckets. """

    @classmethod
    def from_cose_obj(cls, cose_obj: list):
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
        self._phdr = phdr.copy()
        self._uhdr = uhdr.copy()

        # can be plaintext or ciphertext
        if type(payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = payload

    @property
    def phdr(self) -> dict:
        return self._phdr

    @phdr.setter
    def phdr(self, new_phdr: dict) -> None:
        if type(new_phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr = new_phdr.copy()

    @property
    def uhdr(self) -> dict:
        return self._uhdr

    @uhdr.setter
    def uhdr(self, new_uhdr: dict) -> None:
        if type(new_uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr = new_uhdr.copy()

    def phdr_update(self, phdr_params: dict) -> None:
        if type(phdr_params) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr.update(phdr_params)

    def uhdr_update(self, uhdr_params: dict) -> None:
        if type(uhdr_params) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr.update(uhdr_params)

    def encode_phdr(self) -> bytes:
        """ Encode the protected header. """

        if len(self._phdr):
            return cbor2.dumps(self._phdr, default=self._special_cbor_encoder)
        else:
            return b''

    @classmethod
    def _special_cbor_encoder(cls, encoder, special_hdr_value):
        encoder.encode(int(special_hdr_value))

    @classmethod
    def _parse_header(cls, hdr):
        new_hdr = {}
        for k, v in hdr.items():
            parse_func = attr.headers.parser(attr.headers.CoseHeaderKeys(k))
            if parse_func is not None:
                new_hdr[attr.headers.CoseHeaderKeys(k)] = parse_func(v)
            else:
                new_hdr[attr.headers.CoseHeaderKeys(k)] = v

        return new_hdr

    def encode_uhdr(self) -> dict:
        """ Encode the unprotected header. """

        return self._uhdr

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError()
