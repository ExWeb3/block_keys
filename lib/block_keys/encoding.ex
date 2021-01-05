defmodule BlockKeys.Encoding do
  @moduledoc """
  This module contains Base58check encoding and decoding functions for extended keys
  """

  @version %{
    mainnet_private: <<4, 136, 173, 228>>,
    mainnet_public: <<4, 136, 178, 30>>,
    testnet_private: <<4, 53, 131, 148>>,
    testnet_public: <<4, 53, 135, 207>>
  }

  alias BlockKeys.Base58

  def base58_encode(bytes, version_prefix \\ "") do
    Base58.encode_check(bytes, version_prefix)
  end

  def decode_extended_key(key) do
    decoded_key =
      Base58.decode(key)
      |> :binary.encode_unsigned()

    <<
      version_number::binary-4,
      depth::binary-1,
      fingerprint::binary-4,
      index::binary-4,
      chain_code::binary-32,
      key::binary-33,
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

  def encode_extended_key(version_number, depth, fingerprint, index, chain_code, key) do
    key = prefix_private_key(key, version_number)

    version_number
    |> Kernel.<>(depth)
    |> Kernel.<>(fingerprint)
    |> Kernel.<>(index)
    |> Kernel.<>(chain_code)
    |> Kernel.<>(key)
    |> base58_encode
  end

  def encode_public(%{
        derived_key: derived_key,
        child_chain: child_chain,
        fingerprint: fingerprint,
        index: index,
        depth: depth,
        version_number: version_number
      }) do
    encode_extended_key(
      version_number,
      depth,
      fingerprint,
      <<index::32>>,
      child_chain,
      derived_key
    )
  end

  def encode_public({:error, _message} = payload), do: payload

  def encode_private(%{
        derived_key: derived_key,
        child_chain: child_chain,
        fingerprint: fingerprint,
        index: index,
        depth: depth,
        version_number: version_number
      }) do
    encode_extended_key(
      version_number,
      depth,
      fingerprint,
      <<index::32>>,
      child_chain,
      derived_key
    )
  end

  def public_version_number(:mainnet), do: @version.mainnet_public
  def public_version_number(:testnet), do: @version.testnet_public

  def private_version_number(:mainnet), do: @version.mainnet_private
  def private_version_number(:testnet), do: @version.testnet_private

  defp prefix_private_key(key, version) do
    if version == private_version_number(:mainnet) or version == private_version_number(:testnet) do
      <<0>> <> key
    else
      key
    end
  end
end
