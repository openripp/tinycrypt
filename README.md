# tinycrypt of flutter

Pure dart lang lib.

It's a port of C-lib tinycrypt: https://github.com/intel/tinycrypt

# overview

== detail please see: https://github.com/intel/tinycrypt ==

TinyCrypt Cryptographic Library

Overview
The TinyCrypt Library provides an implementation for targeting constrained devices with a minimal set of standard cryptography primitives, as listed below. To better serve applications targeting constrained devices, TinyCrypt implementations differ from the standard specifications (see the Important Remarks section for some important differences). Certain cryptographic primitives depend on other primitives, as mentioned in the list below.

Aside from the Important Remarks section below, valuable information on the usage, security and technicalities of each cryptographic primitive are found in the corresponding header file.

SHA-256:
Type of primitive: Hash function.
Standard Specification: NIST FIPS PUB 180-4.
Requires: --
HMAC-SHA256:
Type of primitive: Message authentication code.
Standard Specification: RFC 2104.
Requires: SHA-256
HMAC-PRNG:
Type of primitive: Pseudo-random number generator (256-bit strength).
Standard Specification: NIST SP 800-90A.
Requires: SHA-256 and HMAC-SHA256.
AES-128:
Type of primitive: Block cipher.
Standard Specification: NIST FIPS PUB 197.
Requires: --
AES-CBC mode:
Type of primitive: Encryption mode of operation.
Standard Specification: NIST SP 800-38A.
Requires: AES-128.
AES-CTR mode:
Type of primitive: Encryption mode of operation.
Standard Specification: NIST SP 800-38A.
Requires: AES-128.
AES-CMAC mode:
Type of primitive: Message authentication code.
Standard Specification: NIST SP 800-38B.
Requires: AES-128.
AES-CCM mode:
Type of primitive: Authenticated encryption.
Standard Specification: NIST SP 800-38C.
Requires: AES-128.
CTR-PRNG:
Type of primitive: Pseudo-random number generator (128-bit strength).
Standard Specification: NIST SP 800-90A.
Requires: AES-128.
ECC-DH:
Type of primitive: Key exchange based on curve NIST p-256.
Standard Specification: RFC 6090.
Requires: ECC auxiliary functions (ecc.h/c).
ECC-DSA:
Type of primitive: Digital signature based on curve NIST p-256.
Standard Specification: RFC 6090.
Requires: ECC auxiliary functions (ecc.h/c).