# Simple Library for PKCS#10 and PKCS#12

This library provides following functions:

* Create RSA key pair
* PKCS#10 certificate signing request
* PKCS#12 generation and download

# Use Cases

This library should replace deprecated keygen tag in
browsers. Primary use case is for PKIs which needs
to create a browser certificate.

# Security Considerations

PKCS#10 tools creates private key in local browser.
Therefore PKCS#12 works only if also PKCS#10 of
that library is used.
Due to the fact that some browser are accepting only
3DES encrypted PKCS#12 private key, it encodes it
with 3DES.

# How To Use

Create a PKCS#10 CSR and let it sign by your PKI.
PKI should respond with a certificate. Then
use PKCS#12 to offer user a downloadble PKCS#12
file.
