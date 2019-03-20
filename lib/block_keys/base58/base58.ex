defmodule BlockKeys.Base58 do
  @moduledoc """
  Documentation for Base58.
  """

  alias BlockKeys.Base58

  defdelegate encode(data, hash \\ ""), to: Base58.Encoder
  defdelegate decode(data), to: Base58.Encoder

  defdelegate encode_check(data, prefix), to: Base58.Check
  defdelegate decode_check(data, length \\ 25), to: Base58.Check
end
