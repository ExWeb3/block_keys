defmodule BlockKeys.Base58 do
  @alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @length String.length(@alphabet)

  def encode(data, hash \\ "")
  def encode(0, hash), do: hash
  def encode(data, hash) when is_binary(data) do
    data
    |> :binary.decode_unsigned()
    |> encode(hash)
    |> prepend_zeros(data)
  end
  def encode(data, hash) do
    data
    |> div(@length)
    |> encode(extended_hash(data, hash))
  end

  defp extended_hash(data, hash) do
    @alphabet
    |> String.at(rem(data, @length))
    |> Kernel.<>(hash)
  end

  defp prepend_zeros(hash, data) do
    hash
    |> encode_zeros()
    |> Kernel.<>(hash)
  end

  defp encode_zeros(data) do
    data
    |> leading_zeros()
    |> duplicate_zeros()
  end

  defp leading_zeros(data) do
    data
    |> :binary.bin_to_list()
    |> Enum.find_index(&(&1 != 0))
  end

  defp duplicate_zeros(count) do
    @alphabet
    |> String.first()
    |> String.duplicate(count)
  end
end
