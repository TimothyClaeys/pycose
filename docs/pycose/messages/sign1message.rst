Sign1
=====

:class:`~pycose.messages.sign1message.Sign1Message` messages are used when there is a single signature attached to the basic
COSE structure, consisting of headers and payload. Receivers must implicitly know the public key to verify the message
since no additional key information is transported.

The payload can either be included in the message or remain detached.
Detached payloads must be provided as `detached_payload` argument during signing and verification.

.. image:: ../../../images/sign1.png
    :width: 650px
    :align: center

.. module:: pycose.messages.sign1message

.. autoclass:: Sign1Message
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
