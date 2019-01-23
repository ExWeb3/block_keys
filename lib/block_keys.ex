defmodule BlockKeys do
  alias BlockKeys.Bip32Mnemonic

  @private_version_number <<4, 136, 173, 228>>
  @public_version_number  <<4, 136, 178, 30>>
  @mersenne_prime 2_147_483_647

  def derive(extended_key, << "m/", path::binary >>) do
    decoded_key = Bip32Mnemonic.parse_extended_key(extended_key)

    if decoded_key.version_number === @public_version_number do
      {:error, "Cannot derive private child key from public key" }
    else
      path
      |> String.split("/")
      |> _derive(extended_key)
    end
  end

  def derive(<< "xpub", _rest::binary >> = extended_key, << "M/", path::binary >>) do
    path
    |> String.split("/")
    |> _derive(extended_key)
  end

  def derive(<< "xprv", _rest::binary >> = extended_key, << "M/", path::binary >>) do
    child_prv = 
      path
      |> String.split("/")
      |> _derive(extended_key)

    Bip32Mnemonic.master_public_key(child_prv)
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
    else
      err -> err
    end
  end
end
