defmodule BlockKeys.Ethereum.Address do
  @moduledoc """
  Converts a public extended key into an Ethereum Address
  Follows EIP-55 checksum address encoding: https://eips.ethereum.org/EIPS/eip-55
  """

  alias BlockKeys.{Encoding, Crypto}

  def from_xpub(xpub) do
    xpub
    |> maybe_decode()
    |> decompress()
    |> ExKeccak.hash_256()
    |> to_address()
  end

  def valid_address?("0x" <> address = full_address) when byte_size(address) == 40 do
    case to_checksum_address(full_address) do
      {:ok, checksum} -> checksum == full_address
      _ -> false
    end
  end

  def valid_address?(_address), do: false

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
    {:ok, checksum_address} =
      "0x"
      |> Kernel.<>(address |> Base.encode16(case: :lower))
      |> to_checksum_address()

    checksum_address
  end

  defp to_checksum_address("0x" <> address) when byte_size(address) == 40 do
    address = String.downcase(address)

    checksum =
      Enum.zip(
        String.graphemes(address),
        String.graphemes(address |> ExKeccak.hash_256() |> Base.encode16(case: :lower))
      )
      |> Enum.map_join(fn {each_address, each_hash} ->
        cond do
          String.match?(each_address, ~r/[0-9]/) ->
            each_address

          String.match?(each_address, ~r/[a-f]/) and elem(Integer.parse(each_hash, 16), 0) >= 8 ->
            String.upcase(each_address)

          String.match?(each_address, ~r/[a-f]/) ->
            each_address
        end
      end)

    {:ok, "0x" <> checksum}
  end

  defp to_checksum_address(_address) do
    {:error, "unrecognized address"}
  end
end
