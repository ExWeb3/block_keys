defmodule BlockKeys.Solana do
  @moduledoc """
  Helper module to derive and convert to a Solana Address
  """

  alias BlockKeys.Solana.Address
  alias BlockKeys.CKD

  def address(key, path) do
    CKD.derive(key, path, curve: :ed25519)
    |> Address.from_xpub()
  end
end
