defmodule BlockKeys.Ethereum.Address do
  def from_public_key(public_key) do
    address_bytes = public_key
                    |> keccak256()
    <<_::binary-12, address::binary-20>> = address_bytes

    "0x"
    |> Kernel.<>(address |> Base.encode16(case: :lower))
  end

  def keccak256(data), do: :keccakf1600.hash(:sha3_256, data)
end
