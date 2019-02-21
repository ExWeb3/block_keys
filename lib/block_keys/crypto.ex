defmodule BlockKeys.Crypto do
  @moduledoc """
  This module is a wrapper around cryptographic functions
  """

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
end
