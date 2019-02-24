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
  def derive(<< "xpub", _rest::binary >>, << "m/", _path::binary >>), do: {:error, "Cannot derive private key from public key" }

  def derive(<< "xprv", _rest::binary >> = extended_key, << "M/", path::binary >>) do
    child_prv = 
      path
      |> String.split("/")
      |> _derive(extended_key)

    master_public_key(child_prv)
  end
  def derive(extended_key, path) do
    path
    |> String.replace(~r/m\/|M\//, "")
    |> String.split("/")
    |> _derive(extended_key)
  end

  def _derive([], extended_key), do: extended_key
  def _derive([index | rest], extended_key) do
    index = case Regex.scan(~r/'/, index) do
      [] -> 
        index |> String.to_integer
      _ ->
        hardened_index = 
          index 
          |> String.replace(~r/'/, "")
          |> String.to_integer
          |> Kernel.+(1)
        hardened_index + @mersenne_prime
    end

    with child_key = child_key(extended_key, index) do
      _derive(rest, child_key)
    end
  end

  def child_key({:error, _ } = error, _), do: error
  def child_key(<< "xpub", _rest::binary >> = key, index), do: child_key_public(key, index)
  def child_key(<< "xprv", _rest::binary >> = key, index), do: child_key_private(key, index)
  
  def child_key_public(key, child_index) do
    decoded_key = Encoding.decode_extended_key(key)
    fingerprint = get_fingerprint(decoded_key.key)
    depth       = encode_depth(decoded_key.depth)

    derive_child_pub_key(decoded_key, child_index, depth, fingerprint)
  end

  def encode_depth(depth) do
    depth
    |> :binary.decode_unsigned 
    |> Kernel.+(1)
    |> :binary.encode_unsigned
  end

  def get_fingerprint(key) do
    <<fingerprint::binary-4, _rest::binary>> = Crypto.hash160(key)
    fingerprint
  end

  def derive_child_key(%{ version_number: @public_version_number }, index, _, _) 
  when index > @mersenne_prime do
    {:error, "Cannot do hardened derivation from public key"}
  end

  def derive_child_pub_key(decoded_key, index, depth, fingerprint) do
    {decoded_key.key, decoded_key.chain_code, << index::32>>}
    |> Crypto.hmac512()
    |> Crypto.ec_pubkey_tweak_add(decoded_key.key)
    |> Tuple.append(depth)
    |> Tuple.append(fingerprint)
    |> Tuple.append(index)
    |> Encoding.encode_public()
  end

  def child_key_private(key, child_index) do
    decoded_key = Encoding.decode_extended_key(key)
    <<_prefix::binary-1, parent_priv_key::binary >> = decoded_key.key

    parent_pub_uncompressed = Crypto.public_key(parent_priv_key)
    parent_pub_key          = compress_key(parent_pub_uncompressed)
    fingerprint             = get_fingerprint(parent_pub_key)
    depth                   = encode_depth(decoded_key.depth)
    parent_key              = get_key(child_index, parent_priv_key, parent_pub_key)

    {parent_key, decoded_key.chain_code, << child_index::32>>}
    |> Crypto.hmac512()
    |> prepare_key(decoded_key)
    |> derive_child_priv_key(child_index, depth, fingerprint)
  end

  def derive_child_priv_key({key, chain_code}, index, depth, fingerprint) do
    Encoding.encode_private(key, depth, fingerprint, index, chain_code)
  end

  def get_key(index, private_key, _) when index > @mersenne_prime, do: <<0>> <> private_key
  def get_key(_, _, public_key), do: public_key

  def prepare_key(<< key::256, chain_code::binary >>, decoded_key) do
    p = key
        |> Kernel.+( :binary.decode_unsigned(decoded_key.key))
        |> rem(@order)
        |> :binary.encode_unsigned

    {p, chain_code}
  end

  def compress_key(<< 0x04::8, x::256, y::256 >>) when rem(y, 2) === 0, do: << 0x02::8, x::256 >>  
  def compress_key(<< 0x04::8, x::256, _rest::256 >>), do: << 0x03::8, x::256 >>

  def master_keys(encoded_seed) do
    decoded_seed = encoded_seed
                   |> Base.decode16!(case: :lower)

    << private_key::binary-32, chain_code::binary-32 >> = :crypto.hmac(:sha512, "Bitcoin seed", decoded_seed)
    
    { private_key, chain_code }
  end

  def master_private_key({extended_key, chain_code}) do
    version_number = @private_version_number
    depth = <<0>>
    fingerprint = <<0::32>>
    index = <<0::32>>

    Encoding.encode_extended_key(version_number, depth, fingerprint, index, chain_code, extended_key)
  end

  def master_public_key(<< "xpub", _rest::binary >>), do: {:error, "Cannot derive master public key from another extended public key"}
  def master_public_key(extended_key) do
    decoded_key = Encoding.decode_extended_key(extended_key)
    <<_prefix::binary-1, parent_priv_key::binary >> = decoded_key.key

    {pub_key, _parent_priv_key } = :crypto.generate_key(:ecdh, :secp256k1, parent_priv_key)

    # split into x and y coordinates
    << 0x04::8, x_coordinate::256, y_coordinate::256 >> = pub_key

    pub_key = if rem(y_coordinate, 2) === 0 do
      << 0x02::8, x_coordinate::256 >>  
    else
      << 0x03::8, x_coordinate::256 >>
    end

    Encoding.encode_extended_key(
      @public_version_number, 
      decoded_key.depth, 
      decoded_key.fingerprint, 
      decoded_key.index, 
      decoded_key.chain_code, 
      pub_key
    )
  end

end
