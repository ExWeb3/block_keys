defmodule BlockKeys.Ethereum do
  alias BlockKeys.Ethereum.Address

  def address(key, path) do
    BlockKeys.derive(key, path)
    |> Address.from_xpub
  end
end
