defmodule BlockKeys.Base58Check do
  alias BlockKeys.Base58

  def encode(version, data)

  defp checksum(version, data) do
    version <> data
    |> sha256
    |> sha256
    |> split
  end

  defp split(<< hash :: bytes-size(4), _ :: bits >>), do: hash

  defp sha256(data), do: :crypto.hash(:sha256, data)

  def encode(version, data) do
    version <> data <> checksum(version, data)
    |> Base58.encode
  end
end
