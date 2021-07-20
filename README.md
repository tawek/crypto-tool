## Overview

Simple command line tool to perform cipher/decipher cryptographic operations
using JCE/BC security provider with file-based keystores.

Uses spring shell and kotlin.

## Purpose

Mainly as a sandbox or independent testing of crypto algorithms. 

## How to use

1. checkout
2. mvn spring-boot:run

```
shell> help
....
shell> help <command>
```

One can use `@<scriptfile>` command line parameter or `script <scriptfile>` 
command for scripting.
See spring shell docs.

## Features

- cipher/decipher
- key, key-pair generation (self-signed cert)
- load/save keystore
- JWE encode/decode
- JWS encode/decode
- file i/o
- console i/o
- HEX, BASE64, TEXT (utf-8) data formats
- completion of keys and algorithm names

## CLI Commands

### Cipher operations

- cipher: Cipher data
- decipher: Decipher data

### JWX Commands

- jwe-decode: JWE Decode
- jwe-encode: JWE Encode
- jws-decode: JWS Decode
- jws-encode: JWS Encode

### Keystore operations

- close-keystore: Close keystore
- create-keystore: Create keystore
- delete-key: Delete key
- generate-key: Generate symmetric key
- generate-key-pair: Generate asymmetric key pair
- keystore-info: Keystore information
- list-keys: List keys in keystore
- load-keystore: Load keystore from file
- store-keystore: Store keystore to file

## Todo

- mac, sign, verify
- csr generation, cert import
- x509 extensions
- kid strategies for JWE/JWS
- x5c/x5t JWE/JWS support  
- tests

## License 

ASL 2.0
