defmodule BlockKeys.Ethereum.Address do
  alias BlockKeys.Bip32Mnemonic

  def from_public_key(public_key) do
    public_key
    |> maybe_decode()
    |> keccak256()
    |> to_address
  end

  defp maybe_decode(<< "xpub", _rest::binary >> = encoded_key) do
    decoded_key = encoded_key
                  |> Bip32Mnemonic.parse_extended_key

    decoded_key.key
  end
  defp maybe_decode(key), do: key

  defp to_address(<<_::binary-12, address::binary-20>>) do
    "0x"
    |> Kernel.<>(address |> Base.encode16(case: :lower))
  end

  defp keccak256(data), do: :keccakf1600.hash(:sha3_256, data)
end
