defmodule EthereumAddressTest do
  use ExUnit.Case, async: true

  alias BlockKeys.Ethereum.Address
  alias BlockKeys.CKD

  test "address from mnemonic" do
    root_key =
      BlockKeys.from_mnemonic(
        "nurse grid sister metal flock choice system control about mountain sister rapid hundred render shed chicken print cover tape sister zero bronze tattoo stairs"
      )

    assert root_key ==
             "xprv9s21ZrQH143K35qGjQ6GG1wGHFZP7uCZA1WBdUJA8vBZqESQXQGA4A9d4eve5JqWB5m8YTMcNe8cc7c3FVzDGNcmiabi9WQycbFeEvvJF2D"

    assert CKD.derive(root_key, "M/44'/60'/0'/0/0")
           |> Address.from_xpub() ==
             "0x73Bb50c828fD325c011d740fDe78d02528826156"
  end
end
