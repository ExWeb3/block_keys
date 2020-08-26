defmodule BlockKeys.Mnemonic do
  @moduledoc """
  BIP32 implementation responsible for generating mnemonic phrases, seeds and public / private address trees.
  """

  alias BlockKeys.Crypto

  @pad_length_mnemonic 8
  @pad_length_phrase 11
  @pbkdf2_initial_round 1
  @pbkdf2_rounds 2048

  @allowed_entropy_lengths [33, 66, 99, 132, 165, 198, 231, 264]

  @doc """
  Generates the 24 random manmonic words.

  Can optionally accept entropy string to used to generate a mnemonic.

  ## Examples

      iex> BlockKeys.Bip32Mnemonic.generate_phrase()
      "baby shadow city tower diamond magnet avocado champion crash ..."
      iex> BlockKeys.Mnemonic.generate_phrase("1234")
      "couple muscle snack"

  NOTE: For now the seed can be only generated from 32 bytes entropy
  """
  def generate_phrase(entropy \\ :crypto.strong_rand_bytes(32)) do
    entropy
    |> entropy_hash()
    |> extract_checksum()
    |> append_checksum()
    |> binary_to_bitstring()
    |> mnemonic()
  end

  @doc """
  Takes a string of word phrases and converts them back to 256bit entropy

  ## Examples

      iex> BlockKeys.Mnemonic.entropy_from_phrase("safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"")
      be16fbf0922bf9098c4bfca1764923d10e89054de77091f0af3346f49cf665fe 
  """
  def entropy_from_phrase(phrase) do
    phrase
    |> phrase_to_bitstring()
    |> verify_checksum()
    |> maybe_return_entropy()
  end

  @doc """
  Given a binary of entropy it will generate teh hex encoded seed

  ## Examples
      iex> BlockKeys.Mnemonic.generate_seed("weather neither click twin monster night bridge door immense tornado crack model canal answer harbor weasel winter fan universe burden price quote tail ride"
      "af7f48a70d0ecedc77df984117e336e12f0f0e681a4c95b25f4f17516d7dc4cca456e3a400bd1c6a5a604af67eb58dc6e0eb46fd520ad99ef27855d119dca517"

  """
  def generate_seed(mnemonic, password \\ "") do
    mnemonic
    |> phrase_to_bitstring()
    |> verify_checksum()
    |> pbkdf2_key_stretching(mnemonic, password)
  end

  defp binary_to_bitstring(binary) do
    :binary.bin_to_list(binary)
    |> Enum.map(fn byte -> to_bitstring(byte, @pad_length_mnemonic) end)
    |> Enum.join()
  end

  defp pbkdf2_key_stretching({:error, message}, _, _), do: {:error, message}

  defp pbkdf2_key_stretching({:ok, _binary_mnemonic}, mnemonic, password) do
    salt = <<salt(password)::binary, @pbkdf2_initial_round::integer-32>>
    initial_round = :crypto.hmac(:sha512, mnemonic, salt)

    iterate(mnemonic, @pbkdf2_initial_round + 1, initial_round, initial_round)
    |> Base.encode16(case: :lower)
  end

  defp phrase_to_bitstring(phrase) do
    phrase
    |> phrase_to_list
    |> word_indexes(words())
    |> Enum.map(fn index -> to_bitstring(index, @pad_length_phrase) end)
    |> Enum.join()
  end

  defp maybe_return_entropy({:ok, entropy}), do: Base.encode16(entropy, case: :lower)
  defp maybe_return_entropy({:error, message}), do: {:error, message}

  defp iterate(_entropy, round, _previous, result) when round > @pbkdf2_rounds, do: result

  defp iterate(entropy, round, previous, result) do
    next = :crypto.hmac(:sha512, entropy, previous)
    iterate(entropy, round + 1, next, :crypto.exor(next, result))
  end

  # hash the initial entropy
  defp entropy_hash(sequence), do: {Crypto.sha256(sequence), sequence}

  # extract the first byte (8bits)
  defp extract_checksum({<<checksum::binary-1, _bits::bitstring>>, sequence}),
    do: {checksum, sequence}

  # append the checksum to initial entropy
  defp append_checksum({checksum, sequence}), do: sequence <> checksum

  # convert a byte to a bitstring (8bits)
  defp to_bitstring(byte, pad_length) do
    byte
    |> Integer.to_string(2)
    |> String.pad_leading(pad_length, "0")
  end

  # split the 264bit string into groups of 11, convert to base 10 integer, map it to word list
  defp mnemonic(entropy) do
    Regex.scan(~r/.{11}/, entropy)
    |> List.flatten()
    |> Enum.map(fn binary ->
      word_index(binary, words())
    end)
    |> Enum.join(" ")
  end

  defp word_index(binary, words) do
    binary
    |> String.to_integer(2)
    |> element_at_index(words)
  end

  defp element_at_index(index, words), do: Kernel.elem(words, index)

  defp words do
    :block_keys
    |> Application.app_dir()
    |> Path.join("priv/assets/english.txt")
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Enum.to_list()
    |> List.to_tuple()
  end

  defp bitstring_to_binary(bitstring) do
    Regex.scan(~r/.{8}/, bitstring)
    |> List.flatten()
    |> Enum.map(&String.to_integer(&1, 2))
    |> :binary.list_to_bin()
  end

  defp verify_checksum(ent_bitstring) do
    if String.length(ent_bitstring) in @allowed_entropy_lengths do
      ent_binary = bitstring_to_binary(ent_bitstring)

      {calculated_cs, cs, entropy} =
        case byte_size(ent_binary) do
          33 ->
            <<entropy::binary-32, cs::binary-1>> = ent_binary
            <<calculated_cs::binary-1, _rest::binary>> = Crypto.sha256(entropy)
            {calculated_cs, cs, entropy}

          size ->
            extract_and_compare_checksum(ent_bitstring, div(size, 4))
        end

      if calculated_cs == cs do
        {:ok, entropy}
      else
        {:error, "Checksum is not valid"}
      end
    else
      {:error, "Invalid mnemonic"}
    end
  end

  defp extract_and_compare_checksum(ent_bitstring, cs_length) do
    cs = String.slice(ent_bitstring, -cs_length, String.length(ent_bitstring))
    ent = String.slice(ent_bitstring, 0, String.length(ent_bitstring) - cs_length)

    entropy_hash =
      ent_bitstring
      |> bitstring_to_binary()
      |> Crypto.sha256()

    entropy_bitstring_hash = binary_to_bitstring(entropy_hash)
    calculated_cs = String.slice(entropy_bitstring_hash, 0, cs_length)
    {calculated_cs, cs, bitstring_to_binary(ent)}
  end

  defp phrase_to_list(phrase) do
    phrase
    |> String.split()
    |> Enum.map(&String.trim/1)
  end

  defp word_indexes(phrase_list, words) do
    phrase_list
    |> Enum.map(fn phrase_word ->
      words
      |> Tuple.to_list()
      |> Enum.find_index(fn el -> el === phrase_word end)
    end)
  end

  def salt(password), do: "mnemonic" <> password
end
