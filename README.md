# pycose:snake:  --- CBOR Object Signing and Encryption
[![Python package](https://github.com/TimothyClaeys/pycose/actions/workflows/python-package.yml/badge.svg)](https://github.com/TimothyClaeys/pycose/actions/workflows/python-package.yml)

This project is a Python implementation of the IETF CBOR Encoded Message Syntax (COSE). COSE has reached RFC status and is now available at RFC 8152.


## Installation

```bash
$ pip install cose
```

:warning:**WARNING**:warning:: There is package on [PyPI](https://pypi.org/) called `pycose` which contains old code from this repository. Since I am not the maintainer I cannot update that package or remove it.

## What is COSE ?
CBOR Encoded Message Syntax (COSE) is a data format for concise representation of small messages [RFC 8152](https://tools.ietf.org/html/rfc8152). COSE is optimized for low power devices. The messages can be encrypted, MAC'ed and signed. There are 6 different types of COSE messages:

- **Encrypt0**: An encrypted COSE message with a single recipient. The payload and AAD are protected by a shared CEK (Content Encryption Keys)
- **Encrypt**: An encrypted COSE message can have multiple recipients. For each recipient the CEK is encrypted with a KEK (Key Encryption Key) - using AES key wrap - and added to the message.
- **MAC0**: An authenticated COSE message with one recipient.
- **MAC**: An authenticated COSE message that can have multiple recipients. For each recipient, the authentication key is encrypted with a KEK and added to the message.
- **Sign0**: A signed COSE message with a single signature.
- **Sign**: A COSE message that has been signed by multiple entities (each signature is carried in a COSE signature structure, added to the message).

A basic COSE message consists of 2 _information_ _buckets_ and the _payload_:

- **Protected header**: This message field contains information that needs to be protected. This information is taken into account during the encryption, calculation of the MAC or the signature.
- **Unprotected header**: The information contained in the unprotected header is not protected by the cryptographic algorithms.
- **Payload**: Contains the payload of the message, protected (mac'ed, signed or encrypted) by the cryptographic algorithms.

Additionally, based on the message type, other message fields can be added:

- _MAC_ or _signature_ (for **MAC0** or **Sign1** messages)
- _COSE recipients_ or _COSE signatures_ (for **MAC**, **Encrypt**, and **Sign** messages)

## Examples
A set of examples can be found [here](https://pycose.readthedocs.io/en/latest/examples.html)

## Cryptography

The project depends on [pyca/cryptography](https://github.com/pyca/cryptography) for all cryptographic operations, except the deterministic ECDSA algorithm. For deterministic ECDSA `cose` uses [python-ecdsa](https://github.com/warner/python-ecdsa). 

## Documentation

More documentation on COSE and the `cose` API can be found at: https://pycose.readthedocs.io

