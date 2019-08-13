defmodule BlockKeys.CKD do
  @moduledoc """
  This module derives children keys given an extended public or private key and a path
  """

  alias BlockKeys.{Crypto, Encoding}

  @mersenne_prime 2_147_483_647
  @order 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  @private_version_number <<4, 136, 173, 228>>
  @public_version_number <<4, 136, 178, 30>>

  @doc """
  Returns a Base58 encode check child extended key given an extended key and a path

  ### Examples

        iex> BlockKeys.derive("xprv9s21ZrQH143K3BwM39ubv3fkaHxCN6M4roETEg68Jviq9AnbRjmqVAF4qJHkoLqgSv2bNqYTnRNY9yBQhjNYceZ1NxiDe8WcNJAeWetCvfR", "m/44'/0'/0'")
        "xprv9yAYtNSBnu2ojv5BR1b8T39t8oPnbzG8H8CbEHnhBhoXWf441nRA3zDW7PFBL4wkz7CNqtbhr4YVnLuSquiR1QPJgk72jVN8uZ4S2UkuLVk"
  """
  def derive(<<"xpub", _rest::binary>>, <<"m/", _path::binary>>),
    do: {:error, "Cannot derive private key from public key"}

  def derive(<<"xprv", _rest::binary>> = extended_key, <<"M/", path::binary>>) do
    path
    |> String.split("/")
    |> _derive(extended_key)
    |> master_public_key()
  end

  def derive(extended_key, path) do
    path
    |> String.replace(~r/m\/|M\//, "")
    |> String.split("/")
    |> _derive(extended_key)
  end

  defp _derive([], extended_key), do: extended_key

  defp _derive([index | rest], extended_key) do
    index =
      case Regex.scan(~r/'/, index) do
        [] -> String.to_integer(index)
        _ -> parse_index(index)
      end

    with child_key = child_key(extended_key, index) do
      _derive(rest, child_key)
    end
  end

  def child_key({:error, _} = error, _), do: error
  def child_key(<<"xpub", _rest::binary>> = key, index), do: child_key_public(key, index)
  def child_key(<<"xprv", _rest::binary>> = key, index), do: child_key_private(key, index)

  def child_key_public(key, child_index) do
    key
    |> Encoding.decode_extended_key()
    |> put_decoded_key()
    |> put_fingerprint(%{index: child_index})
    |> put_depth()
    |> put_child_key_and_chaincode_pub()
    |> ec_point_addition()
    |> check_path()
    |> Encoding.encode_public()
  end

  def child_key_private(key, child_index) do
    key
    |> Encoding.decode_extended_key()
    |> slice_prefix()
    |> put_uncompressed_parent_pub(%{index: child_index})
    |> put_compressed_parent_pub()
    |> put_fingerprint()
    |> put_depth()
    |> put_private_or_public_key()
    |> put_child_key_and_chaincode_priv()
    |> calculate_order()
    |> Encoding.encode_private()
  end

  def master_keys(encoded_seed) do
    decoded_seed =
      encoded_seed
      |> Base.decode16!(case: :lower)

    <<private_key::binary-32, chain_code::binary-32>> =
      :crypto.hmac(:sha512, "Bitcoin seed", decoded_seed)

    {private_key, chain_code}
  end

  def master_private_key({extended_key, chain_code}) do
    version_number = @private_version_number
    depth = <<0>>
    fingerprint = <<0::32>>
    index = <<0::32>>

    Encoding.encode_extended_key(
      version_number,
      depth,
      fingerprint,
      index,
      chain_code,
      extended_key
    )
  end

  def master_public_key(<<"xpub", _rest::binary>>),
    do: {:error, "Cannot derive master public key from another extended public key"}

  def master_public_key(key) do
    decoded_key = Encoding.decode_extended_key(key)

    data =
      decoded_key
      |> slice_prefix()
      |> put_uncompressed_parent_pub(%{index: decoded_key.index})
      |> put_compressed_parent_pub()

    Encoding.encode_extended_key(
      @public_version_number,
      decoded_key.depth,
      decoded_key.fingerprint,
      decoded_key.index,
      decoded_key.chain_code,
      data.parent_pub_key
    )
  end

  defp parse_index(index) do
    index
    |> String.replace(~r/'/, "")
    |> String.to_integer()
    |> Kernel.+(1)
    |> Kernel.+(@mersenne_prime)
  end

  defp put_decoded_key(decoded_key) do
    %{decoded_key: decoded_key}
  end

  defp put_private_or_public_key(%{index: index, parent_priv_key: priv_key} = data)
       when index > @mersenne_prime do
    data
    |> Map.merge(%{derived_key: <<0>> <> priv_key})
  end

  defp put_private_or_public_key(%{parent_pub_key: pub_key} = data) do
    data
    |> Map.merge(%{derived_key: pub_key})
  end

  defp calculate_order(%{derived_key: key, decoded_key: %{key: parent_key}} = data) do
    derived_key =
      key
      |> Kernel.+(:binary.decode_unsigned(parent_key))
      |> rem(@order)
      |> :binary.encode_unsigned()
      |> pad_bytes(32)

    data
    |> Map.merge(%{derived_key: derived_key})
  end

  defp pad_bytes(content, total_bytes) when byte_size(content) >= total_bytes, do: content

  defp pad_bytes(content, total_bytes) do
    bits = (total_bytes - byte_size(content)) * 8
    <<0::size(bits)>> <> content
  end

  defp slice_prefix(%{key: <<_prefix::binary-1, parent_priv_key::binary>>} = decoded_key) do
    %{parent_priv_key: parent_priv_key}
    |> Map.merge(%{decoded_key: decoded_key})
  end

  defp put_uncompressed_parent_pub(%{parent_priv_key: parent_priv_key} = data, index) do
    data
    |> Map.merge(%{parent_pub_key_uncompressed: Crypto.public_key(parent_priv_key)})
    |> Map.merge(index)
  end

  defp put_compressed_parent_pub(%{parent_pub_key_uncompressed: key} = data) do
    data
    |> Map.merge(%{parent_pub_key: compress_key(key)})
  end

  defp check_path(%{index: index, decoded_key: %{version_number: @public_version_number}})
       when index > @mersenne_prime do
    {:error, "Cannot do hardened derivation from public key"}
  end

  defp check_path(data), do: data

  defp put_fingerprint(%{parent_pub_key: key} = data) do
    <<fingerprint::binary-4, _rest::binary>> = Crypto.hash160(key)

    data
    |> Map.merge(%{fingerprint: fingerprint})
  end

  defp put_fingerprint(%{decoded_key: %{key: key} = decoded_key} = data, index) do
    <<fingerprint::binary-4, _rest::binary>> = Crypto.hash160(key)

    data
    |> Map.merge(%{fingerprint: fingerprint, decoded_key: decoded_key})
    |> Map.merge(index)
  end

  defp put_depth(%{decoded_key: %{depth: depth}} = data) do
    depth =
      depth
      |> :binary.decode_unsigned()
      |> Kernel.+(1)
      |> :binary.encode_unsigned()

    data
    |> Map.merge(%{depth: depth})
  end

  defp put_child_key_and_chaincode_pub(
         %{decoded_key: %{chain_code: chain_code, key: key}, index: index} = data
       ) do
    <<derived_key::binary-32, child_chain::binary-32>> =
      :crypto.hmac(:sha512, chain_code, key <> <<index::32>>)

    data
    |> Map.merge(%{child_chain: child_chain, derived_key: derived_key})
  end

  defp put_child_key_and_chaincode_priv(
         %{decoded_key: %{chain_code: chain_code}, index: index, derived_key: derived_key} = data
       ) do
    <<derived_key::256, child_chain::binary>> =
      :crypto.hmac(:sha512, chain_code, derived_key <> <<index::32>>)

    data
    |> Map.merge(%{child_chain: child_chain, derived_key: derived_key})
  end

  defp ec_point_addition(%{derived_key: derived_key, decoded_key: %{key: key}} = data) do
    {:ok, child_key} = Crypto.ec_point_addition(key, derived_key)

    data
    |> Map.merge(%{derived_key: child_key})
  end

  defp compress_key(<<0x04::8, x::256, y::256>>) when rem(y, 2) === 0, do: <<0x02::8, x::256>>
  defp compress_key(<<0x04::8, x::256, _rest::256>>), do: <<0x03::8, x::256>>
end
