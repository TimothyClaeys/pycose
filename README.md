# pycose 
[![Build Status](https://travis-ci.org/TimothyClaeys/pycose.svg?branch=master)](https://travis-ci.org/TimothyClaeys/pycose) [![pyversion](https://upload.wikimedia.org/wikipedia/commons/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg)](https://upload.wikimedia.org/wikipedia/commons/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg)

This project is a Python (>=3.6) implementation of the IETF CBOR Encoded Message Syntax (COSE). COSE has reached RFC status and is now available at RFC 8152.

In addition to the core document the following have also become RFCs:

- RFC 8230 How to use RSA algorithms with COSE. (Not currently supported)

The project is implemented using pyca/cryptography for the crypto libraries and additionally uses python-ecdsa (https://github.com/warner/python-ecdsa) for the deterministic ECDSA algorithm. The pyca/cryptography currently only supports the ECDSA version that requires strong random numbers for each signature.

## What is COSE
CBOR Encoded Message Syntax (COSE) is a data format for concise representation of small messages. It is optimized for low power devices. COSE messages can be encrypted, MAC'ed and signed. There are 6 different types of COSE messages:

- **Encrypt0**: An encrypted COSE message with a single recipient. The payload and AAD are protected by a shared CEK (Content Encryption Keys)
- **Encrypt**: An encrypted COSE message can have multiple recipients. For each recipient the CEK is encrypted with a KEK (Key Encryption Key) - using AES key wrap - and added to the message.
- **MAC0**: An authenticated COSE message with one recipient.
- **MAC**: An authenticated COSE message that can have multiple recipients. For each recipient, the authentication key is encrypted with a KEK and added to the message.
- **Sign0**: A signed COSE message with a single signature.
- **Sign**: A COSE message that has been signed by multiple entities (each signature is carried in a COSE signature structure, added to the message).

A basic COSE message consists of 2 information buckets and the payload:

- **Protected header**: This message field contains information that needs to be protected. This information is taken into account during the encryption, calculation of the MAC or the signature.
- **Unprotected header**: The information contained in the unprotected header is not protected by the cryptographic algorithms.
- **Payload**: Contains the payload of the message (protected by the cryptographic algorithms).

Additionally, based on the message type, other message fields can be added:

- MAC or signature
- COSE recipients or COSE signatures

## How to install

1. Clone the repository
2. `cd COSE-PYTHON`
3. Run `git submodule init` && `git submodule update`
4. Install the python package (pycose) with pip: `pip3 install -e .`

You should now be able to run the unit tests in the `tests/` directory,
e.g.:

`python3 test_crypto.py`

## Usage

