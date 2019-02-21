defmodule BlockKeys.Ethereum do
  alias BlockKeys.Ethereum.Address
  alias BlockKeys.CKD

  def address(key, path) do
    CKD.derive(key, path)
    |> Address.from_xpub
  end
end
