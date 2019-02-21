defmodule BlockKeys.Ethereum do
  @moduledoc """
  Helper module to derive and convert to an Ethereum Address
  """

  alias BlockKeys.Ethereum.Address
  alias BlockKeys.CKD

  def address(key, path) do
    CKD.derive(key, path)
    |> Address.from_xpub
  end
end
