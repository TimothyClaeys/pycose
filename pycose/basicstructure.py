from copy import deepcopy

import cbor

from pycose.attributes import CoseAttrs


class BasicCoseStructure:
    """Description of the basic COSE information buckets."""

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs()):
        self._protected_header = p_header
        self._encoded_protected_header = self.__encode_protected_header()
        self._unprotected_header = u_header
        self._encoded_unprotected_header = self.__encode_unprotected_header()

    @property
    def protected_header(self):
        """Returns the protected header."""
        return self._protected_header

    @protected_header.setter
    def protected_header(self, new_value):
        """Sets the protected header value. """
        if isinstance(new_value, dict) or isinstance(new_value, CoseAttrs):
            self._protected_header = deepcopy(new_value)
        else:
            raise TypeError("The buckets can only be set with Python dictionaries or CoseAttributes.")

    @property
    def encoded_protected_header(self):
        """Returns the protected header as a CBOR encoded serialized map."""
        return self.__encode_protected_header()

    @property
    def unprotected_header(self):
        """Returns the unprotected header as a Python dictionary."""
        return self._unprotected_header

    @unprotected_header.setter
    def unprotected_header(self, new_value):
        """Sets the unprotected header value."""
        if isinstance(new_value, dict) or isinstance(new_value, CoseAttrs):
            self._unprotected_header = deepcopy(new_value)
        else:
            raise TypeError("The buckets can only be set with dictionaries or CoseAttributes.")

    @property
    def encoded_unprotected_header(self):
        """Returns the protected header as a cbor encoded serialized map."""
        return self.__encode_unprotected_header()

    def add_to_headers(self, dct, where):
        if where == "PROTECTED":
            for key in dct:
                self._protected_header[key] = dct[key]
            self._encoded_protected_header = self.__encode_protected_header()
        if where == "UNPROTECTED":
            for key in dct:
                self._unprotected_header[key] = dct[key]
            self._encoded_unprotected_header = self.__encode_protected_header()

    def remove_from_headers(self, dct, where):
        if where == "PROTECTED":
            for key in dct:
                if key in self._protected_header and self._protected_header[key] == dct[key]:
                    del self._protected_header[key]
        if where == "UNPROTECTED":
            for key in dct:
                if key in self._unprotected_header and self._unprotected_header[key] == dct[key]:
                    del self._unprotected_header[key]

    def find_in_headers(self, header, label):
        if label in header:
            return self._protected_header[label]
        else:
            return None

    # PRIVATE METHODS #

    def __encode_protected_header(self):
        """Encode the protected header. No action need to be taken for the unprotected header."""
        if len(self._protected_header) == 0:
            to_be_returned = bytes()
        else:
            to_be_returned = cbor.dumps(self.__convert_to_coseattrs(self._protected_header))

        return to_be_returned

    def __encode_unprotected_header(self):
        """Encode the protected header. No action need to be taken for the unprotected header."""
        if len(self._unprotected_header) == 0:
            to_be_returned = {}
        else:
            to_be_returned = self.__convert_to_coseattrs(self._unprotected_header)

        return to_be_returned

    @staticmethod
    def __convert_to_coseattrs(dictionary):
        if isinstance(dictionary, dict):
            new_coseattrs = CoseAttrs()
            for key in dictionary:
                new_coseattrs[key] = dictionary[key]
            return new_coseattrs
        elif isinstance(dictionary, CoseAttrs):
            return dictionary
        else:
            raise TypeError("Can only accept objects of the type dict or CoseAttrs.")
