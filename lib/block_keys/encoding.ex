defmodule BlockKeys.Encoding do
  @moduledoc """
  This module contains Base58check encoding and decoding functions for extended keys
  """

  @private_version_number <<4, 136, 173, 228>>
  @public_version_number <<4, 136, 178, 30>>

  def base58_encode(bytes, version_prefix \\ "") do
    Base58Check.encode58check(version_prefix, bytes)
  end

  def decode_extended_key(key) do
    decoded_key =
      Base58Check.decode58(key)
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
    key =
      case version_number do
        @private_version_number() ->
          <<0>> <> key

        @public_version_number() ->
          key
      end

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
        depth: depth
      }) do
    encode_extended_key(
      @public_version_number,
      depth,
      fingerprint,
      <<index::32>>,
      child_chain,
      derived_key
    )
  end

  def encode_public({:error, message} = payload), do: payload

  def encode_private(%{
        derived_key: derived_key,
        child_chain: child_chain,
        fingerprint: fingerprint,
        index: index,
        depth: depth
      }) do
    encode_extended_key(
      @private_version_number,
      depth,
      fingerprint,
      <<index::32>>,
      child_chain,
      derived_key
    )
  end
end
