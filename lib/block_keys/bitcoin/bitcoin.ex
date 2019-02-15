defmodule BlockKeys.Bitcoin do
  alias BlockKeys.Bitcoin.Address
  alias BlockKeys.Derivation

  def address(key, path) do
    Derivation.derive(key, path)
    |> Address.from_xpub
  end
end
