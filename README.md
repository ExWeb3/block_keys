# BlockKeys

BlockKeys is an Elixir implementation of BIP44 Multi-Account Hierarchy for Deterministic Wallets.
Currently it supports Bitcoin and Ethereum but will be extended to support a [large number of coin types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) of coins in the future.

For low level details check the [Wiki](https://github.com/AgileAlpha/block_keys/wiki).

## What is this good for ?

The purpose of HD wallets is to increase anonymity by generating different addresses each time you transact. For Bitcoin this means generating
new addresses when you receive funds but also generating unique change addresses (this would prevent someone from knowing how much bitcoin you 
sent in a transactions because the to address and change address will both not be tied to your sending address). This is pseudo-anonymity because
there are other ways of clustering transactions in order to de-anonymize your transactions.

The second use case for this library is to allow online stores or exchanges to receive crypto currency payments without using a hot wallet. 
You only need a Master Public Key deployed on your server in order to generate addresses. In case of a security breach the only danger is
the attacker now has the ability to check the balances for all your accounts but not steal any coins (really just a privacy issue here).
Using the Master Public Key you can also setup a watch-only wallet in order to reconcile the payments you receive. 

# How to use this

## Create a master node

Generate the mnemonic phrase and the master private key

```
{mnemonic, master_key} = BlockKeys.Wallet.generate()
```

## Generate Master Public Key

Generate a master public key that you can use to generate addresses

### Bitcoin

```
path = "M/44'/0'/0'"
xpub = BlockKeys.derive(master_key, path)
```

### Ethereum

```
path = "M/60'/0'/0'"
xpub = BlockKeys.derive(master_key, path)
```

## Generating addresses from Master Public Key

Generally you would export the master public key and keep it on your live server so that you can generate addresses for payments or deposits.

This is just an example of how you would generate some sample addresses

### Bitcoin

```
path = "M/0/0"
address = BlockKeys.Bitcoin.address(xpub, path)
```

### Ethereum

```
path = "M/0/0"
address = BlockKeys.Ethereum.address(xpub, path)
```

## Path and derivations

You will notice that we used different paths for generating the master private key vs addresses. This is because our initial derivation path includes some hardened paths in order to prevent any downstream generation of addresses for specific paths. For example, the coin code path is hardened in order to prevent anyone from generating a tree of addresses for a different coin given our master public key.

Essentially out master public key will only be able to generate trees of addresses from un-hardened paths.

Our address path

```
M/0/0
```

Is equivalent to

```
M/60'/0'/0'/0/0
```
