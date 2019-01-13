# BlockKeys

**WIP Elixir implementation of BIP44 Blockchain Wallet**

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

The mnemonic generator from random entropy is currently implemented. 
The BIP32Mnemonic module will output 24 mnemonic words corresponding to a 256bit entropy.

```
iex(1)> BlockKeys.Bip32Mnemonic.generate
["ski", "theory", "kind", "crucial", "entire", "genre", "narrow", "walk",
 "road", "match", "help", "virtual", "float", "peace", "stumble", "clock",
 "hub", "elephant", "flight", "unique", "envelope", "hungry", "dog", "verify"]

```

The steps to generate the mnemonic words are the following:

- Create random sequence of 256bits
- Create the checksum by taking the first 8 bits of the entropy SHA256 hash
- Add checksum to the end of the random sequence (now 264bit)
- Split result into 11 bit sequences -> 24 sequences
- Map each 11 bit value to a word in the predefined dictionary

