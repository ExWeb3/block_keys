defmodule BlockKeys.Bitcoin do
  alias BlockKeys.Bitcoin.Address

  def address(key, path) do
    BlockKeys.derive(key, path)
    |> Address.from_xpub
  end
end
