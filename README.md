# COSE-PYTHON
This project is a Python implementation of the IETF CBOR Encoded Message Syntax (COSE). COSE has reached RFC status and is now available at RFC 8152.

In addition to the core document the following have also become RFCs:

- RFC 8230 How to use RSA algorithms with COSE. (Not currently supported)

The project is implemented using pyca/cryptography for the crypto libraries and additionally uses python-ecdsa (https://github.com/warner/python-ecdsa) for the deterministic ecdsa algorithm. The pyca/cryptography currently only supports the ecdsa version that requires strong random numbers for each signature.



