Mac
===

:class:`~pycose.messages.macmessage.MacMessage` messages are used when there are multiple receivers or additional information
required to authenticate/validate the message. The basic COSE structure, consisting of headers and (encrypted) payload,
is extended with a list of :class:`~pycose.messages.recipient.CoseRecipient` structures.

.. module:: pycose.messages.macmessage

.. autoclass:: MacMessage
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
