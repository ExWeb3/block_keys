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

  # tweak the child key by adding the parent key to it
  def ec_point_addition(parent_key, child_key) do
    with {:ok, decompressed_parent_key} <- ExSecp256k1.public_key_decompress(parent_key),
         {:ok, key} <- ExSecp256k1.public_key_tweak_add(decompressed_parent_key, child_key) do
      ExSecp256k1.public_key_compress(key)
    end
  end

  def public_key(private_key) do
    {:ok, public_key} = ExSecp256k1.create_public_key(private_key)
    public_key
  end

  def public_key_decompress(public_key) do
    ExSecp256k1.public_key_decompress(public_key)
  end
end
