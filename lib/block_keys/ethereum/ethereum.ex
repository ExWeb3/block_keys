defmodule BlockKeys.Ethereum do
  alias BlockKeys.Ethereum.Address
  alias BlockKeys.Derivation

  def address(key, path) do
    Derivation.derive(key, path)
    |> Address.from_xpub
  end
end
