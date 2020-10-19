Encrypt
=======


:class:`~cose.messages.encmessage.EncMessage` messages are used when there are multiple receivers or additional information
required to decrypt the message. The basic COSE structure, consisting of headers and (encrypted) payload, is extended with
a list of :class:`~cose.messages.recipient.CoseRecipient` structures.

.. module:: cose.messages.encmessage

.. autoclass:: EncMessage
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
