# CDDL fragment MACed Messages with Implicit Key
#
# COSE_Mac = [
#       Headers,
#       payload : bstr / nil,
#       tag : bstr
# ]
#

from typing import Optional, TYPE_CHECKING

from pycose import utils
from pycose.messages import cosemessage, maccommon

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK


@cosemessage.CoseMessage.record_cbor_tag(17)
class Mac0Message(maccommon.MacCommon):
    context = "MAC0"
    cbor_tag = 17

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool) -> 'Mac0Message':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.auth_tag = cose_obj.pop(0)

        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 *args,
                 **kwargs):
        if phdr is None:
            phdr = {}
        if uhdr is None:
            uhdr = {}

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

    def encode(self, tag: bool = True, mac: bool = True, *args, **kwargs) -> bytes:
        """ Encode and protect the COSE_Mac0 message. """

        if mac:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.compute_tag()]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        res = super(Mac0Message, self).encode(message, tag)
        return res

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Mac0: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, ' \
               f'{utils.truncate(self.auth_tag)}]>'
