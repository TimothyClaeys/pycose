import copy

from coseparams import CoseParams

import cbor


class Attribute:
    def __init__(self):
        self._protected_header = CoseParams()
        self._unprotected_header = CoseParams()
        self._external_aad = b''


    @property
    def protected_header(self):
        """
        Returns the protected header
        :return: protected header as a serialized map or empty byte string
        """
        return self.encode_headers('PROTECTED')

    @protected_header.setter
    def protected_header(self, new_value):
        new_value = copy.deepcopy(new_value)
        if new_value is not None and len(new_value) != 0:
            if isinstance(new_value, dict):
                self._protected_header = CoseParams()
                for key, value in new_value.items():
                    self._protected_header[key] = value
            elif isinstance(new_value, bytes):
                new_value = cbor.loads(new_value)
                if isinstance(new_value, dict):
                    self._protected_header = CoseParams()
                    for key, value in new_value.items():
                        self._protected_header[key] = value
                else:
                    raise TypeError("CBOR decoding didn't result in the expected object")
        else:
            self._protected_header = CoseParams()

    @property
    def unprotected_header(self):
        return self.encode_headers('UNPROTECTED')

    @unprotected_header.setter
    def unprotected_header(self, new_value):
        if new_value is not None:
            new_value = copy.deepcopy(new_value)
            self._unprotected_header = CoseParams()
            for key, value in new_value.items():
                self._unprotected_header[key] = value
        else:
            self._unprotected_header = CoseParams()

    @property
    def external_aad(self):
        return self._external_aad

    @external_aad.setter
    def external_aad(self, new_external_aad):
        if new_external_aad is None or len(new_external_aad) == 0:

            self._external_aad = bytes()
        else:
            if isinstance(new_external_aad, str):
                self._external_aad = cbor.loads(new_external_aad)
            elif isinstance(new_external_aad, bytes):
                self._external_aad = new_external_aad
            else:
                raise TypeError("Input must be of type str or bytes")

    def add_to_headers(self, label, value, where):
        if where == "PROTECTED":
            self._protected_header[label] = value

        if where == "UNPROTECTED":
            self._unprotected_header[label] = value

    def remove_from_headers(self, label):
        if not isinstance(label, str) and not isinstance(label, int):
            raise ValueError("label must be a string or an integer")

        if label in self._protected_header:
            del self._protected_header[label]

        if label in self._unprotected_header:
            del self._unprotected_header[label]

    def find_in_headers(self, label):
        if label in self._protected_header:
            return self._protected_header[label]
        elif label in self._unprotected_header:
            return self._unprotected_header[label]
        else:
            raise KeyError("Attribute not in headers " + str(label))

    def encode_headers(self, where):
        if where == 'PROTECTED':
            if len(self._protected_header) == 0:
                ret_value = bytes()
            else:
                ret_value = cbor.dumps(self._protected_header)
            return ret_value
        elif where == 'UNPROTECTED':
            return self._unprotected_header
        else:
            raise ValueError("Not a COSE header type")
