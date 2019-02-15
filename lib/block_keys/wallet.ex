defmodule BlockKeys.Wallet do
  alias BlockKeys.Bip32Mnemonic

  def generate() do
    phrase = Bip32Mnemonic.generate_phrase()
    
    %{
      mnemonic: phrase,
      root_key: from_mnemonic(phrase)
    }
  end

  def from_mnemonic(phrase) do
    phrase
    |> Bip32Mnemonic.generate_seed()
    |> Bip32Mnemonic.master_keys()
    |> Bip32Mnemonic.master_private_key
  end
end
