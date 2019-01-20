defmodule BlockKeys do
  alias BlockKeys.Bip32Mnemonic

  @private_version_number <<4, 136, 173, 228>>
  @public_version_number  <<4, 136, 178, 30>>

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

  def derive(extended_key, << "M/", path::binary >>) do
    decoded_key = Bip32Mnemonic.parse_extended_key(extended_key)
    
    xpub = case decoded_key.version_number do
      @private_version_number ->
        Bip32Mnemonic.master_public_key(extended_key)
      @public_version_number ->
        extended_key
    end

    path
    |> String.split("/")
    |> _derive(xpub)
  end

  def _derive([], extended_key), do: extended_key
  def _derive([index | rest], extended_key) do

    with child_key = Bip32Mnemonic.child_key(extended_key, index |> String.to_integer) do
      _derive(rest, child_key)
    end
  end
end
