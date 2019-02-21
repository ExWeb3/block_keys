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
  def child_key(<< "xpub", _rest::binary >> = extended_key, child_index), do: child_key_public(Encoding.decode_extended_key(extended_key), child_index)
  def child_key(<< "xprv", _rest::binary >> = extended_key, child_index), do: child_key_private(Encoding.decode_extended_key(extended_key), child_index)
  
  def child_key_public(decoded_key, child_index) do
    parent_pub_key  = decoded_key.key

    <<fingerprint::binary-4, _rest::binary>> = Crypto.hash160(parent_pub_key)

    index = << child_index::32>>
    depth = decoded_key.depth 
            |> :binary.decode_unsigned 
            |> Kernel.+(1)
            |> :binary.encode_unsigned

    if (index |> :binary.decode_unsigned > @mersenne_prime) && (decoded_key.version_number !== @private_version_number) do
      {:error, "Cannot do hardened derivation from public key"}
    else

      hash_value = :crypto.hmac(:sha512, decoded_key.chain_code, parent_pub_key <> index)
      << derived_key::binary-32, child_chain::binary-32 >> = hash_value

      {:ok, public_child_key } = :libsecp256k1.ec_pubkey_tweak_add(parent_pub_key, derived_key)


      Encoding.encode_extended_key(@public_version_number, depth, fingerprint, index, child_chain, public_child_key)
    end
  end

  def child_key_private(decoded_key, child_index) do
    <<_prefix::binary-1, parent_priv_key::binary >> = decoded_key.key

    {parent_pub_key, _parent_priv_key } = :crypto.generate_key(:ecdh, :secp256k1, parent_priv_key)

    # split into x and y coordinates
    << 0x04::8, x_coordinate::256, y_coordinate::256 >> = parent_pub_key

    parent_pub_key = if rem(y_coordinate, 2) === 0 do
      << 0x02::8, x_coordinate::256 >>  
    else
      << 0x03::8, x_coordinate::256 >>
    end

    index = << child_index::32>>
    depth = decoded_key.depth 
            |> :binary.decode_unsigned 
            |> Kernel.+(1)
            |> :binary.encode_unsigned

    parent_key = if index |> :binary.decode_unsigned > @mersenne_prime do
      <<0>> <> parent_priv_key
    else
      parent_pub_key
    end

    hash_value = :crypto.hmac(:sha512, decoded_key.chain_code, parent_key <> index)

    << derived_key::256, child_chain::binary >> = hash_value

    p = derived_key
        |> Kernel.+(decoded_key.key |> :binary.decode_unsigned)
        |> rem(@order)
        |> :binary.encode_unsigned

    <<fingerprint::binary-4, _rest::binary>> = Crypto.hash160(parent_pub_key)

    Encoding.encode_extended_key(@private_version_number, depth, fingerprint, index, child_chain, p)
  end

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
