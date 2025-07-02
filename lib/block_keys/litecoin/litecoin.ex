defmodule BlockKeys.Litecoin do
  @moduledoc """
  Helper module to derive and convert to a Litecoin Address
  """

  alias BlockKeys.Litecoin.Address
  alias BlockKeys.CKD

  def address(key, path) do
    CKD.derive(key, path)
    |> Address.from_xpub()
  end
end
