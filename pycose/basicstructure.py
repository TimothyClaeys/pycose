from copy import deepcopy

import cbor

from pycose.attributes import CoseAttrs


class BasicCoseStructure:
    """Description of the basic COSE information buckets."""
    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs):
        self._protected_header = self._convert_to_coseattrs(p_header)
        self._encoded_protected_header = self._encode_protected_header()
        self._unprotected_header = self._convert_to_coseattrs(u_header)

    @property
    def protected_header(self):
        """Returns the protected header"""
        return self._protected_header

    @protected_header.setter
    def protected_header(self, new_value):
        """Sets the protected header value. Takes a dictionary object and copies its values in a CoseAttrs object."""
        new_value = deepcopy(new_value)
        for key in new_value:
            self._protected_header[key] = new_value[key]

    @property
    def encoded_protected_header(self):
        """Returns the protected header as a cbor encoded serialized map."""
        return self._encode_protected_header()

    @property
    def unprotected_header(self):
        """Returns the unprotected header as a dictionary."""
        return self._unprotected_header

    @unprotected_header.setter
    def unprotected_header(self, new_value):
        """Sets the unprotected header value."""
        new_value = deepcopy(new_value)
        for key in new_value:
            self._unprotected_header[key] = new_value[key]

    def add_to_headers(self, label, value, where):
        if where == "PROTECTED":
            self.protected_header[label] = value

        if where == "UNPROTECTED":
            self.unprotected_header[label] = value

    def remove_from_headers(self, label):
        if not isinstance(label, str) and not isinstance(label, int):
            raise ValueError("label must be a string or an integer")

        if label in self._protected_header:
            del self._protected_header[label]
        elif label in self._unprotected_header:
            del self._unprotected_header[label]
        else:
            raise KeyError("Attribute not in headers " + str(label))

    def find_in_headers(self, label):
        if label in self._protected_header:
            return self._protected_header[label]
        elif label in self._unprotected_header:
            return self._unprotected_header[label]
        else:
            raise KeyError("Attribute not in headers " + str(label))

    def _encode_protected_header(self):
        """Encode the protected header. No action need to be taken for the unprotected header."""
        if len(self._protected_header) == 0:
            to_be_returned = bytes()
        else:
            to_be_returned = cbor.dumps(self._protected_header)

        return to_be_returned

    @staticmethod
    def _convert_to_coseattrs(dictionary):
        if isinstance(dictionary, dict):
            new_coseattrs = CoseAttrs()
            for key in dictionary:
                new_coseattrs[key] = dictionary[key]
            return new_coseattrs
        elif isinstance(dictionary, CoseAttrs):
            return dictionary
        else:
            raise ValueError("Can only accept objects of the type dict or CoseAttrs.")
