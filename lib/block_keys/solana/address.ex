defmodule BlockKeys.Solana.Address do
  @moduledoc """
  Converts a public extended key into a Solana Address
  """

  alias BlockKeys.Base58

  def from_xpub(xpub) do
    xpub
    |> maybe_decode()
    |> Base58.encode()
  end

  def valid_address?(address) when byte_size(address) in 32..44 do
    public_key = address |> BlockKeys.Base58.decode() |> :binary.encode_unsigned()
    Ed25519.on_curve?(public_key)
  end

  def valid_address?(_address), do: false

  defp maybe_decode(<<"xpub", encoded_key::binary>> = _xpub) do
    encoded_key
    |> decode_extended_key()
    |> Map.fetch!(:key)
  end

  defp maybe_decode(key), do: key

  defp decode_extended_key(key) do
    decoded_key =
      Base58.decode(key)
      |> :binary.encode_unsigned()

    <<
      version_number::binary-4,
      depth::binary-1,
      fingerprint::binary-4,
      index::binary-4,
      chain_code::binary-32,
      key::binary-32,
      _checksum::binary-4
    >> = decoded_key

    %{
      version_number: version_number,
      depth: depth,
      fingerprint: fingerprint,
      index: index,
      chain_code: chain_code,
      key: key
    }
  end
end
