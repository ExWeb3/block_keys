defmodule BlockKeys.Bitcoin do
  @moduledoc """
  Helper module to derive and convert to a Bitcoin Address
  """

  alias BlockKeys.Bitcoin.Address
  alias BlockKeys.CKD

  def address(key, path) do
    CKD.derive(key, path)
    |> Address.from_xpub()
  end
end
