# BlockKeys

**WIP Elixir implementation of BIP44 Blockchain Wallet**

Do not use this, it's just a learning implementation.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `bitcoin_addresses` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:block_keys, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/bitcoin_addresses](https://hexdocs.pm/bitcoin_addresses).

## BIP32 Mnemonic

### Generate 24 word phrase

The mnemonic generator from random entropy is currently implemented. 
The BIP32Mnemonic module will output 24 mnemonic words corresponding to a 256bit entropy.

```
iex(1)> BlockKeys.Bip32Mnemonic.generate_phrase
"baby shadow city tower diamond magnet avocado champion crash evolve circle chair boring runway remain fantasy finger impose crumble profit excuse group twist purse"
```

The steps to generate the mnemonic words are the following:

- Create random sequence of 256bits
- Create the checksum by taking the first 8 bits of the entropy SHA256 hash
- Add checksum to the end of the random sequence (now 264bit)
- Split result into 11 bit sequences -> 24 sequences
- Map each 11 bit value to a word in the predefined dictionary

### Restore entropy given phrase

```
iex(1)> BlockKeys.Bip32Mnemonic.entropy_from_phrase("fade joy announce clever yellow special near expand bus jealous memory usual just daughter bring oppose tone bind cloud mosquito route warfare engage champion")
<<81, 207, 16, 37, 21, 79, 241, 161, 228, 226, 129, 30, 238, 242, 43, 248, 23,
  150, 111, 135, 12, 220, 228, 66, 200, 175, 200, 11, 201, 238, 18, 145>>
```

The steps to restore the entropy given the phrase are:

- Split the string into individual words
- Look up the index in the word dictionary for each word and create a list
- Convert each element in that list to a binary string of 0s and 1s
- Remove checksum (last 8 bits)
- Split the bitstring into groups of 8 bits
- Convert each chunk into a byte (8 bits)
- Convert the byte list into a binary
