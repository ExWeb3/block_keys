defmodule BlockKeys.Wallet do
  alias BlockKeys.Bip32Mnemonic

  def generate() do
    phrase = Bip32Mnemonic.generate_phrase()

    %{ private_key: private_key, chain_code: chain_code } = 
      phrase 
      |> Bip32Mnemonic.generate_seed(phrase)
      |> Bip32Mnemonic.master_keys

    {
      phrase,
      Bip32Mnemonic.master_private_key(private_key, chain_code)
    }
  end
end
