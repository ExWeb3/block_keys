defmodule BlockKeys.Bip32Mnemonic do
  @pad_length_mnemonic 8
  @pad_length_phrase 11
  @pbkdf2_rounds 2048
  @pbkdf2_initial_round 1

  @private_version_number <<4, 136, 173, 228>>
  @public_version_number  <<4, 136, 178, 30>>

  @order 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  @mersenne_prime 2_147_483_647

  def generate_phrase do
    entropy = SecureRandom.random_bytes(32)

    entropy
      |> entropy_hash()
      |> extract_checksum()
      |> append_checksum(entropy)
      |> :binary.bin_to_list()
      |> Enum.map(fn byte -> to_bitstring(byte, @pad_length_mnemonic) end)
      |> Enum.join()
      |> mnemonic()
  end

  # hash the initial entropy
  defp entropy_hash(sequence), do: :libsecp256k1.sha256(sequence)

  # extract the first byte (8bits)
  defp extract_checksum(<< checksum :: size(8), _bits :: bitstring >>), do: checksum

  # append the checksum to initial entropy
  defp append_checksum(checksum, entropy), do: entropy <> << checksum >>

  # convert a byte to a bitstring (8bits)
  def to_bitstring(byte, pad_length) do
    byte
    |> Integer.to_string(2)
    |> String.pad_leading(pad_length, "0")
  end

  # split the 264bit string into groups of 11, convert to base 10 integer, map it to word list
  def mnemonic(entropy) do
    Regex.scan(~r/.{11}/, entropy)
    |> List.flatten()
    |> Enum.map(fn binary -> 
      word_index(binary, words())
    end)
    |> Enum.join(" ")
  end

  def word_index(binary, words) do
    binary
    |> String.to_integer(2)
    |> element_at_index(words)
  end

  defp element_at_index(index, words), do: Kernel.elem(words, index)

  def words do
    "./assets/english.txt"
    |> File.stream!
    |> Stream.map(&String.trim/1)
    |> Enum.to_list
    |> List.to_tuple
  end

  # convert the phrase to entropy
  def entropy_from_phrase(phrase) do
    phrase
    |> phrase_to_list
    |> word_indexes(words())
    |> Enum.map(fn index -> to_bitstring(index, @pad_length_phrase) end)
    |> Enum.join()
    |> remove_checksum
    |> entropy()
  end

  def entropy(bitstring) do
    Regex.scan(~r/.{8}/, bitstring)
    |> List.flatten
    |> Enum.map(&String.to_integer(&1, 2))
    |> :binary.list_to_bin()
  end

  def remove_checksum(bitstring), do: String.slice(bitstring, 0..255)

  def phrase_to_list(phrase) do
    phrase
    |> String.split()
    |> Enum.map(&String.trim/1)
  end

  def word_indexes(phrase_list, words) do
    phrase_list
    |> Enum.map(fn phrase_word ->
      words
      |> Tuple.to_list
      |> Enum.find_index(fn el -> el === phrase_word end)
    end)
  end

  def salt(password), do: "mnemonic" <> password

  def generate_seed(entropy, password \\ "") do
    salt = <<salt(password)::binary, 1::integer-32>>
    initial_round = :crypto.hmac(:sha512, entropy, salt)
    iterate(entropy, @pbkdf2_initial_round + 1, initial_round, initial_round)
    |> Base.encode16(case: :lower)
  end

  def master_keys(encoded_seed) do
    decoded_seed = encoded_seed
                   |> Base.decode16!(case: :lower)

    << private_key::binary-32, chain_code::binary-32 >> = :crypto.hmac(:sha512, "Bitcoin seed", decoded_seed)
    
    %{
      private_key: private_key,
      chain_code: chain_code
    }
  end

  def master_private_key(extended_key, chain_code) do
    version_number = @private_version_number 
    depth = <<0>>
    fingerprint = <<0::32>>
    index = <<0::32>>

    version_number <> depth <> fingerprint <> index <> chain_code <> <<0>> <> extended_key
    |> base58_encode
  end

  def base58_encode(bytes, version_prefix \\ "") do
    Base58Check.encode58check(version_prefix, bytes)
  end

  def master_public_key(extended_key) do
    decoded_key = parse_extended_key(extended_key)
    <<_prefix::binary-1, parent_priv_key::binary >> = decoded_key.key

    {pub_key, _parent_priv_key } = :crypto.generate_key(:ecdh, :secp256k1, parent_priv_key)

    # split into x and y coordinates
    << 0x04::8, x_coordinate::256, y_coordinate::256 >> = pub_key

    pub_key = if rem(y_coordinate, 2) === 0 do
      << 0x02::8, x_coordinate::256 >>  
    else
      << 0x03::8, x_coordinate::256 >>
    end

    @public_version_number <> decoded_key.depth <> decoded_key.fingerprint <> decoded_key.index <> decoded_key.chain_code <> pub_key
    |> base58_encode
  end

  def iterate(_entropy, round, _previous, result) when round > @pbkdf2_rounds, do: result
  def iterate(entropy, round, previous, result) do
    next = :crypto.hmac(:sha512, entropy, previous)
    iterate(entropy, round + 1, next, :crypto.exor(next, result))
  end

  def parse_extended_key(key) do
    decoded_key = 
      Base58Check.decode58(key)
      |> :binary.encode_unsigned

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

  def hash160(data) do
    data
    |> sha256()
    |> ripemd160()
  end

  def sha256(data) do
    :crypto.hash(:sha256, data)
  end

  def ripemd160(data) do
    :crypto.hash(:ripemd160, data)
  end

  def child_key({:error, _ } = error, _), do: error
  def child_key(<< "xpub", _rest::binary >> = extended_key, child_index), do: child_key_public(parse_extended_key(extended_key), child_index)
  def child_key(<< "xprv", _rest::binary >> = extended_key, child_index), do: child_key_private(parse_extended_key(extended_key), child_index)
  
  def child_key_public(decoded_key, child_index) do
    parent_pub_key  = decoded_key.key

    <<fingerprint::binary-4, _rest::binary>> = hash160(parent_pub_key)

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

      @public_version_number <>  depth <> fingerprint <> index <> child_chain <> public_child_key
      |> base58_encode
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

    <<fingerprint::binary-4, _rest::binary>> = hash160(parent_pub_key)

    @private_version_number <>  depth <> fingerprint <> index <> child_chain <> <<0>> <> p
    |> base58_encode
  end
end
