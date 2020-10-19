.. pycose documentation master file, created by
   sphinx-quickstart on Fri Aug 21 15:42:18 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

**********************************************************************
``cose`` a Python implementation of CBOR Object Signing and Encryption
**********************************************************************

What is COSE?
*************

CBOR Object Signing and Encryption (COSE_) is a data format for concise representation of small messages. It is optimized for
low-power devices. COSE messages can be encrypted, MAC'ed and signed. There are 6 different types of COSE messages:

.. _COSE: https://tools.ietf.org/html/rfc8152

- **Encrypt0**: An encrypted COSE message with a single recipient. The payload and AAD are protected by a shared CEK (Content Encryption Keys)
- **Encrypt**: An encrypted COSE message can have multiple recipients. For each recipient the CEK is encrypted with a KEK (Key Encryption Key) - using AES key wrap - and added to the message.

- **MAC0**: An authenticated COSE message with one recipient.
- **MAC**: An authenticated COSE message that can have multiple recipients. For each recipient, the authentication key is encrypted with a KEK and added to the message.
- **Sign0**: A signed COSE message with a single signature.
- **Sign**: A COSE message that has been signed by multiple entities (each signature is carried in a COSE signature structure, added to the message).

A basic COSE message consists of 2 information buckets and the payload:

.. image:: ../images/basic_structure.png
    :width: 400px
    :align: center

- **Protected header**: This message field contains information that needs to be protected. This information is taken into account during the encryption, calculation of the MAC or the signature.
- **Unprotected header**: The information contained in the unprotected header is not protected by the cryptographic algorithms.
- **Payload**: Contains the payload of the message (protected by the cryptographic algorithms).

Additionally, based on the message type, other message fields can be added:

- *MAC* or *signature* (for **MAC0** or **Sign1** messages)
- *COSE recipients* or *COSE signatures* (for **MAC**, **Encrypt**, and **Sign** messages)


Besides the different COSE messages, the RFC also defines COSE Key objects. COSE Keys are used to store and transport
cryptographic keys. There are three main key types:

- **EC2 key**
- **OKP keys**
- **Symmetric keys**

.. toctree::
   :maxdepth: 2
   :caption: The cose package (API)

   cose/messages/index.rst
   cose/keys/index.rst
   cose/attributes/index.rst

.. toctree::
   :maxdepth: 2
   :caption: Miscellaneous

   installation.rst
   LICENSE.rst
   CONTRIBUTING.rst
   glossary.rst
