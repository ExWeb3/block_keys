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
    ec_module().ec_pubkey_tweak_add(parent_key, child_key)
  end

  def public_key(private_key) do
    {:ok, public_key} = ec_module().ec_pubkey_create(private_key, :uncompressed)
    public_key
  end

  def public_key_decompress(public_key) do
    ec_module().ec_pubkey_decompress(public_key)
  end

  defp ec_module do
    Application.fetch_env!(:block_keys, :ec_module)
  end
end
