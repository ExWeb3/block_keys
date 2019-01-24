defmodule BlockKeys do
  alias BlockKeys.Bip32Mnemonic
  @mersenne_prime 2_147_483_647

  def derive(<< "xpub", _rest::binary >>, << "m/", _path::binary >>), do: {:error, "Cannot derive private key from public key" }

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
