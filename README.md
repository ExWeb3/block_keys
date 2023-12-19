# BlockKeys

[![Build Status](https://travis-ci.com/AgileAlpha/block_keys.svg?branch=master)](https://travis-ci.com/AgileAlpha/block_keys)

BlockKeys is an Elixir implementation of BIP44 Multi-Account Hierarchy for Deterministic Wallets.
Currently it supports Bitcoin and Ethereum but will be extended to support a [large number of coin types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) of coins in the future.

For low level details check the [Wiki](https://github.com/AgileAlpha/block_keys/wiki).

## Installation

Add the dependency to your `mix.exs`:

```
def deps do
  [
    {:block_keys, "~> 1.0.1"}
  ]
end
```

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

## Mnemonic Lenghts

This library supports a wide range of mnemonic sizes: from 3 words to 24 words. **Please note that anything less than 12 word mnemonics are not
recommended for generating blockchain wallets.**

## Import Ledger Nano mnemonic

**Disclaimer: The mnemonic phrase for you hardware wallet is the key to all your crypto currency stored on that device. Before you go ahead and
input that in this library make sure you audit the code to make sure everything looks legit.**

```
root_key = BlockKeys.from_mnemonic("nurse grid sister metal flock choice system control about mountain sister rapid hundred render shed chicken print cover tape sister zero bronze tattoo stairs")
"xprv9s21ZrQH143K35qGjQ6GG1wGHFZP7uCZA1WBdUJA8vBZqESQXQGA4A9d4eve5JqWB5m8YTMcNe8cc7c3FVzDGNcmiabi9WQycbFeEvvJF2D"
```

### Ethereum Addresses

Now that you have the root private key you can start deriving your account extended keys along with ethereum addresses. Ledger will use the same receive address
unless you recycle it.

```
BlockKeys.CKD.derive(root_key, "M/44'/60'/0'/0/0") |> BlockKeys.Ethereum.Address.from_xpub
"0x73bb50c828fd325c011d740fde78d02528826156"
```

Note that you can generate a master public key by deriving the Account path:

```
master_public_key = BlockKeys.CKD.derive(root_key, "M/44'/60'/0'")
"xpub6C821eJHTSrPMS1sGZ4o5QDDAfWyViQek3fVwUA53FkgndTwjxL7PS1pFP9EdqKpejTZeaQkmxoergebKCpVpPuTdE67Kzn2jZn9AL9TzxD"
```

You can now use this key to generate addresses on a live server that will be in sync with your Ledger

```
BlockKeys.Derivation.CKD.derive(master_public_key, "M/0/0") |> BlockKeys.Ethereum.Address.from_xpub
"0x73bb50c828fd325c011d740fde78d02528826156"
```

We have to use a non hardened path here because we're feeding a public key (hardened paths require a private key for concatenation in the child key derivation function). Note how the address at M/0/0 is the same as our initial M/44'/60'/0'/0/0.

## Create a master node

Generate the mnemonic phrase and the master private key

```
%{mnemonic: mnemonic, root_key: root_key} = BlockKeys.generate()
```

## Generate Master Public Key

Generate a master public key that you can use to generate addresses

### Bitcoin

```
path = "M/44'/0'/0'"
xpub = BlockKeys.CKD.derive(root_key, path)
```

### Ethereum

```
path = "M/60'/0'/0'"
xpub = BlockKeys.CKD.derive(root_key, path)
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

## Contributing

1. [Fork it!](https://github.com/zyield/block_keys)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

ExKeccak is released under the Apache-2.0 License.
