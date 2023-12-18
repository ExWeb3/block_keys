defmodule BlockKeys.Ethereum.Address do
  @moduledoc """
  Converts a public extended key into an Ethereum Address
  """

  alias BlockKeys.{Encoding, Crypto}

  def from_xpub(xpub) do
    xpub
    |> maybe_decode()
    |> decompress()
    |> keccak256()
    |> to_address()
  end

  defp maybe_decode(<<"xpub", _rest::binary>> = encoded_key) do
    decoded_key =
      encoded_key
      |> Encoding.decode_extended_key()

    decoded_key.key
  end

  defp maybe_decode(key), do: key

  defp decompress(key) do
    {:ok, key} = Crypto.public_key_decompress(key)

    <<_prefix::binary-1, pub_key::binary>> = key
    pub_key
  end

  defp to_address(<<_::binary-12, address::binary-20>>) do
    "0x"
    |> Kernel.<>(address |> Base.encode16(case: :lower))
  end

  defp keccak256(data), do: ExKeccak.hash_256(data)
end
