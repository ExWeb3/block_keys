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

  def hmac512({key, chain_code, index}) do
    :crypto.hmac(:sha512, chain_code, key <> index)
  end

  def ec_pubkey_tweak_add(<< derived_key::binary-32, child_chain::binary-32>>, key ) do
    :libsecp256k1.ec_pubkey_tweak_add(key, derived_key)
    |> Tuple.append(child_chain)
  end
end
