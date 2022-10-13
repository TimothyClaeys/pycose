from typing import TYPE_CHECKING, Optional

import attr
import cbor2

if TYPE_CHECKING:
    from pycose.algorithms import _EncAlg

CBOR = bytes


@attr.s(slots=True)
class PartyInfo:
    identity: Optional[bytes] = attr.ib(default=None)
    nonce: Optional[bytes] = attr.ib(default=None)
    other: Optional[bytes] = attr.ib(default=None)

    def encode(self) -> list:
        """ Encodes the party information. """

        return [self.identity, self.nonce, self.other]


@attr.s(slots=True)
class SuppPubInfo:
    _key_data_length: int = attr.ib()
    protected: dict = attr.ib(factory=dict)
    other: bytes = attr.ib(default=b'')

    @property
    def key_data_length(self) -> int:
        """ The length of the derived key in bytes. """

        return self._key_data_length

    @key_data_length.setter
    def key_data_length(self, new_length):
        """ Set the length of the derived key. Must be of length 16, 24 or 32 bytes. """

        if new_length in [16, 24, 32]:
            self._key_data_length = new_length
        else:
            raise ValueError(f"Not a valid key length: {new_length}")

    def __attrs_post__init__(self):
        if self._key_data_length not in [16, 24, 32]:
            raise ValueError(f"Not a valid key length: {self._key_data_length}")

    def encode(self) -> list:
        """ Encodes the supplementary public information. """

        info = [self.key_data_length * 8, cbor2.dumps(self.protected, default=self._custom_cbor_encoder)]
        if self.other != b'':
            info.append(self.other)

        return info

    @classmethod
    def _custom_cbor_encoder(cls, encoder, special_hdr_value):
        encoder.encode(special_hdr_value.identifier)


@attr.s(slots=True)
class CoseKDFContext:
    algorithm: '_EncAlg' = attr.ib()
    supp_pub_info: SuppPubInfo = attr.ib()
    party_u_info: PartyInfo = attr.ib(default=PartyInfo())
    party_v_info: PartyInfo = attr.ib(default=PartyInfo())
    supp_priv_info: bytes = attr.ib(default=b'')

    def encode(self) -> CBOR:
        """ Encodes the COSE KDF context. """
        context = \
            [self.algorithm.identifier, self.party_u_info.encode(), self.party_v_info.encode(),
             self.supp_pub_info.encode()]

        if self.supp_priv_info != b"":
            context.append(self.supp_priv_info)

        return cbor2.dumps(context)
