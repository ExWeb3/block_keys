defmodule BlockKeys.Bitcoin.Address do
  alias BlockKeys.Bip32Mnemonic

  def from_xpub(xpub) do
    xpub
    |> maybe_decode()
    |> Bip32Mnemonic.hash160
    |> Bip32Mnemonic.base58_encode(<< 0 >>)
  end

  defp maybe_decode(<< "xpub", _rest::binary >> = encoded_key) do
    decoded_key = encoded_key
                  |> Bip32Mnemonic.parse_extended_key

    decoded_key.key
  end
  defp maybe_decode(key), do: key
end
