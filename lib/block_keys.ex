defmodule BlockKeys do
  @moduledoc """
  This module derives children keys given an extended public or private key and a path
  """

  alias BlockKeys.Bip32Mnemonic
  @mersenne_prime 2_147_483_647

  defdelegate xpub(ext_prv_key), to: Bip32Mnemonic, as: :master_public_key

  def derive(<< "xpub", _rest::binary >>, << "m/", _path::binary >>), do: {:error, "Cannot derive private key from public key" }


  @doc """
  Returns a Base58 encode check child extended key given an extended key and a path

  ### Examples

        iex> BlockKeys.derive("xprv9s21ZrQH143K3BwM39ubv3fkaHxCN6M4roETEg68Jviq9AnbRjmqVAF4qJHkoLqgSv2bNqYTnRNY9yBQhjNYceZ1NxiDe8WcNJAeWetCvfR", "m/44'/0'/0'")
        "xprv9yAYtNSBnu2ojv5BR1b8T39t8oPnbzG8H8CbEHnhBhoXWf441nRA3zDW7PFBL4wkz7CNqtbhr4YVnLuSquiR1QPJgk72jVN8uZ4S2UkuLVk"
  """
  def derive(<< "xprv", _rest::binary >> = extended_key, << "M/", path::binary >>) do
    child_prv = 
      path
      |> String.split("/")
      |> _derive(extended_key)

    Bip32Mnemonic.master_public_key(child_prv)
  end
  def derive(extended_key, path) do
    path
    |> String.replace(~r/m\/|M\//, "")
    |> String.split("/")
    |> _derive(extended_key)
  end

  def _derive([], extended_key), do: extended_key
  def _derive([index | rest], extended_key) do
    index = case Regex.scan(~r/'/, index) do
      [] -> 
        index |> String.to_integer
      _ ->
        hardened_index = 
          index 
          |> String.replace(~r/'/, "")
          |> String.to_integer
          |> Kernel.+(1)
        hardened_index + @mersenne_prime
    end

    with child_key = Bip32Mnemonic.child_key(extended_key, index) do
      _derive(rest, child_key)
    end
  end
end
