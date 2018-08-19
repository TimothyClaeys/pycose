class KeyParams(dict):
    _keymap_keys = \
        {
            'kty': 1,  # This parameter is used to identify the family of keys for this structure.
            'alg': 3,  # This parameter is used to restrict the algorithm that is used with the key.
            'kid': 2,  # This parameter is used to give an identifier for a key. It's not constructed.
            'key_ops': 4,  # This parameter is defined to restrict the set of operations that a key is to be used for.
            'Base IV': 5  # This parameter is defined to carry the base portion of an IV.
        }

    _keymap_values = \
        {
            1: {"EC2 P-256": 1, "EC2 P-384": 2, "EC2" "P-512": 3},
            3: {
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
            },
            4: {"sign": 1, "verify": 2, "encrypt": 3, "decrypt": 4, "wrap key": 5, "unwrap key": 6, "derive key": 7,
                "derive bits": 8, "MAC create": 9, "MAC verify": 10}
        }

    def __init__(self):
        super(KeyParams, self).__init__()

    def __getitem__(self, label):
        if label in self._keymap_keys:
            label = self._keymap_keys[label]
            value = super(KeyParams, self).__getitem__(label)
            value = ([k for k, v in self._keymap_values[label].items() if v == value][0])
        else:
            value = super(KeyParams, self).__getitem__(label)
        return value

    def __setitem__(self, label, value):
        if label in self._keymap_keys:
            label = self._keymap_keys[label]
            try:
                value = self._keymap_values[label][value]
            except KeyError:
                pass
        if isinstance(value, str):
            super(KeyParams, self).__setitem__(label, bytes(value, 'utf-8'))
        elif isinstance(value, bytes):
            super(KeyParams, self).__setitem__(label, value)
        elif isinstance(value, int):
            super(KeyParams, self).__setitem__(label, value)
        else:
            raise TypeError("Value must be bytes or string")

    def __delitem__(self, label):
        if label in self._keymap_keys:
            label = self._keymap_keys[label]
        super(KeyParams, self).__delitem__(label)

    def __contains__(self, label):
        if label in self._keymap_keys:
            label = self._keymap_keys[label]
        return super(KeyParams, self).__contains__(label)
