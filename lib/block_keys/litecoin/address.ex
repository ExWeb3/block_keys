defmodule BlockKeys.Litecoin.Address do
  @moduledoc """
  Converts a public extended key into a Litecoin Address
  """

  alias BlockKeys.{Crypto, Encoding}

  def from_xpub(xpub) do
    xpub
    |> maybe_decode()
    |> Crypto.hash160()
    |> Encoding.base58_encode(<<48>>)
  end

  defp maybe_decode(<<"xpub", _rest::binary>> = encoded_key) do
    encoded_key
    |> Encoding.decode_extended_key()
    |> Map.fetch!(:key)
  end

  defp maybe_decode(key), do: key
end
