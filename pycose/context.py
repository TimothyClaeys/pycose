import cbor2
from dataclasses import dataclass


@dataclass
class PartyInfo:
    identity: bytes = None
    nonce: bytes = None
    other: bytes = None

    def encode(self):
        return [self.identity, self.nonce, self.other]


@dataclass
class SuppPubInfo:
    _key_data_length: int
    protected: bytes
    other: bytes = None

    @property
    def key_data_length(self):
        return self._key_data_length

    @key_data_length.setter
    def key_data_length(self, new_length):
        if new_length in [128, 192, 256]:
            self._key_data_length = new_length
        else:
            raise ValueError(f"Not a valid key length: {new_length}")

    def __post__init__(self):
        if self._key_data_length not in [128, 192, 256]:
            raise ValueError(f"Not a valid key length: {self._key_data_length}")

    def encode(self):
        info = [self.key_data_length, self.protected]
        if self.other is not None:
            info.append(self.other)

        return info


@dataclass
class CoseKDFContext:
    algorithm_id: int
    party_u_info: PartyInfo
    party_v_info: PartyInfo
    supp_pub_info: SuppPubInfo
    supp_priv_info: bytes = b''

    def encode(self) -> bytes:
        context = \
            [int(self.algorithm_id), self.party_u_info.encode(), self.party_v_info.encode(),
             self.supp_pub_info.encode()]

        if self.supp_priv_info != b"":
            context.append(self.supp_priv_info)

        return cbor2.dumps(context)
