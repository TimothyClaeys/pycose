Examples
========

This page provides some examples on how to use the API to create and from_dict different types of ``cose`` messages.

COSE Encrypt
------------

Example demonstrating the creation of a :class:`~cose.messages.encmessage.EncMessage` with a single
:class:`~cose.messages.recipient.CoseRecipient`. They CEK (Content Encryption Key) is derived using
:class:`~cose.attributes.algorithms.CoseAlgorithms.ECDH_ES_HKDF_256` algorithm.

.. doctest::

    >>> from cose import EncMessage, EC2, CoseEllipticCurves, CoseAlgorithms, CoseHeaderKeys, KeyOps, SymmetricKey
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.Kid: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.Kid: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.Kid: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.encoded_phdr()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
                >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
                >>> from cose.messages.recipient import CoseRecipient, RcptParams

                # the EC2 from the sender (public and private values)
                >>> ec2_ks = EC2(
                ...     key_ops=KeyOps.DERIVE_KEY,
                ...     crv=CoseEllipticCurves.P_256,
                ...     kid=b'meriadoc.brandybuck@buckland.example',
                ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
                ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
                ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

                # the EC2 key (public coordinates) from the receiver
                >>> ec2_kr = EC2(
                ...     crv=CoseEllipticCurves.P_256,
                ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
                ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

                # create a CoseRecipient (details the key derivation algorithm)
                >>> recipient = CoseRecipient(
                ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
                ...     uhdr={
                ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
                ...         CoseHeaderKeys.KID: ec2_ks.kid,
                ...     })

                # set up the COSE KDF context and generate the (KEK) key encryption key.
                >>> context = CoseKDFContext(
                ...     CoseAlgorithms.A256GCM,
                ...     PartyInfo(),
                ...     PartyInfo(),
                ...     SuppPubInfo(256, recipient.phdr_encoded()))

                >>> key_bytes = CoseRecipient.derive_kek(
                ...     ec2_ks,
                ...     ec2_kr,
                ...     CoseAlgorithms.ECDH_ES_HKDF_256,
                ...     context)

                >>> key_bytes  # the key encryption key
                b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encode_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.Kid: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.phdr_encoded()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.phdr_encoded()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.phdr_encoded()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.encoded_phdr()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
            >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
            >>> from cose.messages.recipient import CoseRecipient, RcptParams

            # the EC2 from the sender (public and private values)
            >>> ec2_ks = EC2(
            ...     key_ops=KeyOps.DERIVE_KEY,
            ...     crv=CoseEllipticCurves.P_256,
            ...     kid=b'meriadoc.brandybuck@buckland.example',
            ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
            ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
            ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

            # the EC2 key (public coordinates) from the receiver
            >>> ec2_kr = EC2(
            ...     crv=CoseEllipticCurves.P_256,
            ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
            ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

            # create a CoseRecipient (details the key derivation algorithm)
            >>> recipient = CoseRecipient(
            ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
            ...     uhdr={
            ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
            ...         CoseHeaderKeys.KID: ec2_ks.kid,
            ...     })

            # set up the COSE KDF context and generate the (KEK) key encryption key.
            >>> context = CoseKDFContext(
            ...     CoseAlgorithms.A256GCM,
            ...     PartyInfo(),
            ...     PartyInfo(),
            ...     SuppPubInfo(256, recipient.phdr_encoded()))

            >>> key_bytes = CoseRecipient.derive_kek(
            ...     ec2_ks,
            ...     ec2_kr,
            ...     CoseAlgorithms.ECDH_ES_HKDF_256,
            ...     context)

            >>> key_bytes  # the key encryption key
            b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encode_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encoded_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
        >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
        >>> from cose.messages.recipient import CoseRecipient, RcptParams

        # the EC2 from the sender (public and private values)
        >>> ec2_ks = EC2(
        ...     key_ops=KeyOps.DERIVE_KEY,
        ...     crv=CoseEllipticCurves.P_256,
        ...     kid=b'meriadoc.brandybuck@buckland.example',
        ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
        ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
        ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

        # the EC2 key (public coordinates) from the receiver
        >>> ec2_kr = EC2(
        ...     crv=CoseEllipticCurves.P_256,
        ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
        ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

        # create a CoseRecipient (details the key derivation algorithm)
        >>> recipient = CoseRecipient(
        ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
        ...     uhdr={
        ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
        ...         CoseHeaderKeys.KID: ec2_ks.kid,
        ...     })

        # set up the COSE KDF context and generate the (KEK) key encryption key.
        >>> context = CoseKDFContext(
        ...     CoseAlgorithms.A256GCM,
        ...     PartyInfo(),
        ...     PartyInfo(),
        ...     SuppPubInfo(256, recipient.encoded_phdr()))

        >>> key_bytes = CoseRecipient.derive_kek(
        ...     ec2_ks,
        ...     ec2_kr,
        ...     CoseAlgorithms.ECDH_ES_HKDF_256,
        ...     context)

        >>> key_bytes  # the key encryption key
        b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:
    >>> from cose.attributes.context import CoseKDFContext, PartyInfo, SuppPubInfo
    >>> from cose.messages.recipient import CoseRecipient, RcptParams

    # the EC2 from the sender (public and private values)
    >>> ec2_ks = EC2(
    ...     key_ops=KeyOps.DERIVE_KEY,
    ...     crv=CoseEllipticCurves.P_256,
    ...     kid=b'meriadoc.brandybuck@buckland.example',
    ...     x=EC2.base64decode('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0'),
    ...     y=EC2.base64decode('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw'),
    ...     d=EC2.base64decode('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8'))

    # the EC2 key (public coordinates) from the receiver
    >>> ec2_kr = EC2(
    ...     crv=CoseEllipticCurves.P_256,
    ...     x=EC2.base64decode("mPUKT/bAWGHIhg0TpjjqVsP1rXWQu/vwVOHHtNkdYoA="),
    ...     y=EC2.base64decode("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs="))

    # create a CoseRecipient (details the key derivation algorithm)
    >>> recipient = CoseRecipient(
    ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_ES_HKDF_256},
    ...     uhdr={
    ...         CoseHeaderKeys.EPHEMERAL_KEY: ec2_ks.encode('crv', 'x', 'y'),
    ...         CoseHeaderKeys.KID: ec2_ks.kid,
    ...     })

    # set up the COSE KDF context and generate the (KEK) key encryption key.
    >>> context = CoseKDFContext(
    ...     CoseAlgorithms.A256GCM,
    ...     PartyInfo(),
    ...     PartyInfo(),
    ...     SuppPubInfo(256, recipient.encode_phdr()))

    >>> key_bytes = CoseRecipient.derive_kek(
    ...     ec2_ks,
    ...     ec2_kr,
    ...     CoseAlgorithms.ECDH_ES_HKDF_256,
    ...     context)

    >>> key_bytes  # the key encryption key
    b')\xca\xa72kh:s\xc9\x87wpxf\xd8\x83\x8a:\xdc>?F\xc1\x80\xc5LZ\xaf\x01\xf1\xcc\x0c'

    >>> kek = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.DIRECT, key_ops=KeyOps.WRAP)

    # Instruct how the recipient should derive the CEK (content encryption key) from the KEK.
    # The ECDH_ES_HKDF_256 COSE algorithm uses the kek directly to wrap_cek the payload of the COSE Encrypt message
    >>> rcpt_params = RcptParams(kek)
    >>> cek = SymmetricKey(k=key_bytes, alg=CoseAlgorithms.A256GCM, key_ops=KeyOps.ENCRYPT)

    # create the COSE Encrypt message
    >>> msg = EncMessage(
    ...     phdr={CoseHeaderKeys.ALG: CoseAlgorithms.A256GCM},
    ...     uhdr={CoseHeaderKeys.IV: b'\xc9\xcfM\xf2\xfelc+\xf7\x88d\x13'},
    ...     payload=b"This is the content.",
    ...     recipients=[recipient])

    # encode and wrap_cek the message
    >>> nonce = b'\xc9\xcfM\xf2\xfelc+\xf7\x88d\x13'
    >>> msg.encode(key=cek, nonce=nonce, enc_params=[rcpt_params])
    b'\xd8`\x84C\xa1\x01\x03\xa1\x05L\xc9\xcfM\xf2\xfelc+\xf7\x88d\x13X$>c\xcb\xb9Ey\n:\xaa~\xbd\xa7\x87y\xdf\xb3\x1f\xf2\xefT\xdd\x07\xc2Dz"Kh(\xd3x\x17I\xa7jN\x81\x83D\xa1\x018\x18\xa2 \xa4\x01\x02 \x01!X e\xed\xa5\xa1%w\xc2\xba\xe8)C\x7f\xe38p\x1a\x10\xaa\xa3u\xe1\xbb[]\xe1\x08\xdeC\x9c\x08U\x1d"X \x1eR\xedup\x11c\xf7\xf9\xe4\r\xdf\x9f4\x1b=\xc9\xba\x86\n\xf7\xe0\xca|\xa7\xe9\xee\xcd\x00\x84\xd1\x9c\x04X$meriadoc.brandybuck@buckland.example@'

