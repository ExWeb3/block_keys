defmodule BlockKeys.Base58.Encoder do
  @btc_alphabet '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

  def alphabet, do: @btc_alphabet

  def encode(data, hash \\ "")

  def encode(0, hash), do: hash

  def encode(data, hash) when is_binary(data) do
    encode_zeros(data) <> encode(:binary.decode_unsigned(data), hash)
  end

  def encode(data, hash) do
    character = <<Enum.at(alphabet(), rem(data, 58))>>
    encode(div(data, 58), character <> hash)
  end

  defp encode_zeros(data, acc \\ [])

  defp encode_zeros(<<0, data::bitstring>>, acc) do
    encode_zeros(data, [1 | acc])
  end

  defp encode_zeros(_, acc), do: acc |> Enum.join("")

  def decode(data) when is_binary(data) do
    data
    |> to_charlist
    |> decode(0)
  end

  def decode(_) do
    raise(ArgumentError, "Please use only base58 encoded binary as input")
  end

  defp decode([], acc), do: acc

  defp decode([c | code], acc) do
    decode(code, acc * 58 + find_in_alphabet(c))
  end

  defp find_in_alphabet(char) do
    case Enum.find_index(alphabet(), &(&1 == char)) do
      nil -> raise ArgumentError, "illegal character #{char}"
      index -> index
    end
  end
end
