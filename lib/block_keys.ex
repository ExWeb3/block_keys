defmodule BlockKeys do
  @moduledoc """
  Generates or restores a wallet from mnemonic phrases
  """

  alias BlockKeys.Mnemonic
  alias BlockKeys.CKD

  def generate() do
    phrase = Mnemonic.generate_phrase()
    
    %{
      mnemonic: phrase,
      root_key: from_mnemonic(phrase)
    }
  end

  def from_mnemonic(phrase) do
    phrase
    |> Mnemonic.generate_seed()
    |> CKD.master_keys()
    |> CKD.master_private_key()
  end
end
