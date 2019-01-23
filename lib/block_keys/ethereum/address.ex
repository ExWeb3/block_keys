defmodule BlockKeys.Ethereum.Address do
  alias BlockKeys.Bip32Mnemonic

  def from_public_key(<< "xpub", _rest::binary >> = encoded_key) do
    decoded_key = encoded_key
                  |> Bip32Mnemonic.parse_extended_key

    from_public_key(decoded_key.key)
  end

  def from_public_key(public_key) do
    address_bytes = public_key
                    |> keccak256()
    <<_::binary-12, address::binary-20>> = address_bytes

    "0x"
    |> Kernel.<>(address |> Base.encode16(case: :lower))
  end

  def keccak256(data), do: :keccakf1600.hash(:sha3_256, data)
end
