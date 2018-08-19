class CoseAttrs(dict):
    """
    Class that describes all the COSE attributes. It's a modified dictionary for easy lookup and translation of the
    human readable values.
    """

    _header_keys = \
        {
            'alg': 1,
            'crit': 2,
            'ctyp': 3,
            'kid': 4,
            'iv': 5,
            'partial_iv': 6,
            'counter_signature': 7
        }

    _header_values = \
        {
            1:
                {
                    "direct": -6,
                    "ES256": -7,
                    "ES384": -35,
                    "ES512": -36,
                    "HS256/64": 4,
                    "HS256": 5,
                    "HS384": 6,
                    "HS512": 7,
                    "EdDSA": -8,
                    "AES-MAC128/64": 14,
                    "AES-MAC256/64": 15,
                    "AES-MAC128/128": 25,
                    "AES-MAC256/128": 26,
                    "A128GCM": 1,
                    "A192GCM": 2,
                    "A256GCM": 3
                }
        }

    def __init__(self):
        super(CoseAttrs, self).__init__()

    def __getitem__(self, label):
        if label in self._header_keys:
            label = self._header_keys[label]
            value = super(CoseAttrs, self).__getitem__(label)
            try:
                value = ([k for k, v in self._header_values[label].items() if v == value][0])
            except KeyError:
                pass
        else:
            value = super(CoseAttrs, self).__getitem__(label)
        return value

    def __setitem__(self, label, value):
        if label in self._header_keys:
            label = self._header_keys[label]
            try:
                value = self._header_values[label][value]
            except KeyError:
                pass

        super(CoseAttrs, self).__setitem__(label, value)

    def __delitem__(self, label):
        if label in self._header_keys:
            label = self._header_keys[label]
        super(CoseAttrs, self).__delitem__(label)

    def __contains__(self, label):
        if label in self._header_keys:
            label = self._header_keys[label]
        return super(CoseAttrs, self).__contains__(label)
