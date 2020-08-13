import abc
from enum import IntEnum, unique
from typing import Optional

import cbor2


@unique
class HeaderKeys(IntEnum):
    """ COSE header parameters """
    # Common Parameters
    RESERVED = 0
    ALG = 1
    CRIT = 2
    CONTENT_TYPE = 3
    KID = 4
    IV = 5
    PARTIAL_IV = 6
    COUNTER_SIGNATURE = 7
    COUNTER_SIGNATURE0 = 9
    KID_CONTEXT = 10

    # Elliptic Curve Key identifiers
    EPHEMERAL_KEY = -1
    STATIC_KEY = - 2
    STATIC_KEY_ID = -3

    # HKDF Algorithm Parameters
    SALT = -20

    # Context Algorithm Parameters
    PARTY_U_IDENTITY = -21
    PARTY_U_NONCE = -22
    PARTY_U_OTHER = -23
    PARTY_V_IDENTITY = -24
    PARTY_V_NONCE = -25
    PARTY_V_OTHER = -26


class CoseBase(metaclass=abc.ABCMeta):
    """ Basic COSE information buckets. """

    COSE_HDR_PARSER = {}

    @classmethod
    def record_hdr_value_parser(cls, hdr_param: HeaderKeys):
        """Decorator to record all the CBOR tags dynamically"""

        def decorator(func):
            cls.COSE_HDR_PARSER[hdr_param] = func
            return func

        return decorator

    @classmethod
    def from_cose_obj(cls, cose_obj: list):
        try:
            phdr = cbor2.loads(cose_obj.pop(0))
        except (ValueError, EOFError):
            phdr = {}

        try:
            uhdr = cose_obj.pop(0)
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
            return cbor2.dumps(self._phdr)
        else:
            return b''

    def encode_uhdr(self) -> dict:
        """ Encode the unprotected header. """
        return self._uhdr

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError()
