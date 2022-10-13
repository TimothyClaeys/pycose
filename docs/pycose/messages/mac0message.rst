Mac0
====

:class:`~pycose.messages.mac0message.Mac0Message` messages are used when there is a single receiver. The sender assumes that the receiver knows how
to find/derive the authentication key to verify the appended tag. In case there are multiple receivers (each using a different authentication key) or the
receiver requires more information to find/derive the key :class:`~pycose.messages.macmessage.MacMessage` should be used.

.. module:: pycose.messages.mac0message

.. autoclass:: Mac0Message
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag
