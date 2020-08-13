# Changelog

## v0.2.0

### Breaking changes

  * Break out the Bitcoin and Ethereum address conversion from extended public keys to addresses. If you need this functionality you have to import the separate `block_address` library.

### Bug fixes and improvements

  * Break out `block_base58` into separate library, used as a dependency to this library

## v0.1.3
  
  * Allows a non 32-byte entropy as an optional parameter

## v0.1.2

  * libsecp256k1 updates

## v0.1.1

  * Fixes padding for key derivation

## v0.1.0

Initial release.
