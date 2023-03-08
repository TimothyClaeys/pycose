Sign
====

:class:`~pycose.messages.signmessage.SignMessage` messages are used when there are multiple receivers or additional information
required to validate the message signature. The basic COSE structure, consisting of headers and payload,
is extended with a list of :class:`~pycose.messages.signer.CoseSignature` structures.

The payload can either be included in the message or remain detached.
Detached payloads must be provided as `detached_payload` argument during signing and verification.

.. module:: pycose.messages.signmessage

.. autoclass:: SignMessage
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag

.. module:: pycose.messages.signer

.. autoclass:: CoseSignature
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag

