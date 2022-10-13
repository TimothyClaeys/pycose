Sign
====

:class:`~pycose.messages.signmessage.SignMessage` messages are used when there are multiple receivers or additional information
required to validate the message signature. The basic COSE structure, consisting of headers and payload,
is extended with a list of :class:`~pycose.messages.signer.CoseSignature` structures.

.. module:: pycose.messages.signmessage

.. autoclass:: SignMessage
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag

