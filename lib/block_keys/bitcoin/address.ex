defmodule BlockKeys.Bitcoin.Address do
  alias BlockKeys.Bip32Mnemonic

  def from_public_key(<< "xpub", _rest::binary >> = encoded_key) do
    decoded_key = encoded_key
                  |> Bip32Mnemonic.parse_extended_key

    from_public_key(decoded_key.key)
  end

  def from_public_key(public_key) do
    public_key
    |> Bip32Mnemonic.hash160
    |> Bip32Mnemonic.base58_encode(<< 0 >>)
  end
end
