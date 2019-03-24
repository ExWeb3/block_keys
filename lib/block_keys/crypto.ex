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
    :libsecp256k1.ec_pubkey_tweak_add(parent_key, child_key)
  end

  def public_key(private_key) do
    {public_key, _} = :crypto.generate_key(:ecdh, :secp256k1, private_key)
    public_key
  end
end
