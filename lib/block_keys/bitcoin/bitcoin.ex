defmodule BlockKeys.Bitcoin do
  alias BlockKeys.Bitcoin.Address
  alias BlockKeys.CKD

  def address(key, path) do
    CKD.derive(key, path)
    |> Address.from_xpub
  end
end
