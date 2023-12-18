# Changelog

## v1.0.0

  **Breaking Changes** 

  * Removes support for libsecp256k1 Nif library in favour of the 
  better maitained ex_secp256k1. The Rust based ex_secp256k1 also comes with
  precompiled binaries, making compilation much faster. 


## v0.1.10

  * Adds support for OTP 24

## v0.1.9

  * Adds support for Bitcoin testnet keys

## v0.1.8

  * Minor refactor and fix for a function formatting

## v0.1.7

  * Enables checksums for all phrase sizes: 3, 6, 9, 12, 15, 18, 21 and 24
  * More test coverage for all phrase sizes for seeds and entropy

## v0.1.6

  * Fixes checksum verification for phrases less than 24 words.
  * Adds more tests for phrases of 3 and 12 words.

## v0.1.5

  * Using `keccakf1600_otp23` patched hex package for OTP23 compatibility

## v0.1.3

  * Allows a non 32-byte entropy as an optional parameter

## v0.1.2

  * libsecp256k1 updates

## v0.1.1

  * Fixes padding for key derivation

## v0.1.0

  * Initial release.
