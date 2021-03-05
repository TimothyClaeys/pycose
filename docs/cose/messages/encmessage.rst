Encrypt
=======


:class:`~cose.messages.encmessage.EncMessage` messages are used when there are multiple receivers or additional information
required to decrypt the message. The basic COSE structure, consisting of headers and (encrypted) payload, is extended with
a list of :class:`~cose.messages.recipient.CoseRecipient` structures. Each :class:`~cose.messages.recipient.CoseRecipient`
can optionally contain another list of :class:`~cose.messages.recipient.CoseRecipient` objects.

.. image:: ../../../images/encrypt0.png
    :width: 500px
    :align: center

.. module:: cose.messages.encmessage

.. autoclass:: EncMessage
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
