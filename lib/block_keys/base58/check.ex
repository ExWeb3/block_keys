defmodule BlockKeys.Base58.Check do
  # Based on https://github.com/lukaszsamson/base58check/blob/master/lib/base58check.ex

  alias BlockKeys.Base58.Encoder

  def encode_check(data, prefix) when is_binary(data) and is_binary(prefix) do
    data
    |> maybe_decode_hex()
    |> encode(prefix)
  end

  def encode_check(data, prefix) do
    prefix = encode_unsigned(prefix)
    data = encode_unsigned(data)

    encode_check(data, prefix)
  end

  defp encode_unsigned(data) when is_integer(data), do: :binary.encode_unsigned(data)
  defp encode_unsigned(data), do: data

  defp maybe_decode_hex(data) do
    case Base.decode16(String.upcase(data)) do
      {:ok, bin} -> bin
      :error -> data
    end
  end

  defp encode(data, prefix) do
    (prefix <> data <> generate_checksum(data, prefix))
    |> Encoder.encode()
  end

  defp generate_checksum(data, prefix) do
    (prefix <> data)
    |> sha256
    |> sha256
    |> split
  end

  defp split(<<checksum::bytes-size(4), _::binary-size(28)>>), do: checksum

  defp sha256(data), do: :crypto.hash(:sha256, data)

  def decode_check(data, length \\ 25) do
    decoded = Encoder.decode(data) |> :binary.encode_unsigned()
    size = byte_size(decoded)
    checksum_size = 4
    payload_size = length - 5

    if size < checksum_size do
      raise ArgumentError,
            "address of size #{size} is too short, expected at least #{checksum_size}"
    end

    if size > length do
      raise ArgumentError, "address of size #{size} is too long, expected #{length}"
    end

    padding =
      if size < length do
        for _ <- 1..(length - size), into: <<>>, do: <<0>>
      else
        <<>>
      end

    <<
      prefix::binary-size(1),
      payload::binary-size(payload_size),
      checksum::binary-size(checksum_size)
    >> = padding <> decoded

    generated_checksum = generate_checksum(payload, prefix)

    case valid_checksum?(generated_checksum, checksum) do
      false -> raise ArgumentError, "Checksum is not valid!"
      true -> {prefix, payload}
    end
  end

  defp valid_checksum?(data, checksum), do: data == checksum
end
