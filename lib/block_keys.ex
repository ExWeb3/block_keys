defmodule BlockKeys do
  @moduledoc """
  Generates or restores a wallet from mnemonic phrases
  """

  alias BlockKeys.Mnemonic
  alias BlockKeys.CKD

  def generate(network \\ :mainnet) do
    phrase = Mnemonic.generate_phrase()

    %{
      mnemonic: phrase,
      root_key: from_mnemonic(phrase, network)
    }
  end

  def from_mnemonic(phrase, network \\ :mainnet) do
    phrase
    |> Mnemonic.generate_seed()
    |> CKD.master_keys()
    |> CKD.master_private_key(network)
  end
end
