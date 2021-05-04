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

## Todo

- algorithm name completion
- key label completion  
- mac, sign, verify
- csr generation, cert import
- x509 extensions
- kid strategies for JWE/JWS
- x5c/x5t JWE/JWS support  
- tests
- help for individual parameters

## License 

ASL 2.0
