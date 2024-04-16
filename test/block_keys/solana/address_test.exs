defmodule SolanaAddressTest do
  use ExUnit.Case, async: true

  alias BlockKeys.Solana.Address
  alias BlockKeys.CKD

  test "address from mnemonic" do
    root_key =
      BlockKeys.from_mnemonic(
        "nurse grid sister metal flock choice system control about mountain sister rapid hundred render shed chicken print cover tape sister zero bronze tattoo stairs"
      )

    assert root_key ==
             "xprv9s21ZrQH143K35qGjQ6GG1wGHFZP7uCZA1WBdUJA8vBZqESQXQGA4A9d4eve5JqWB5m8YTMcNe8cc7c3FVzDGNcmiabi9WQycbFeEvvJF2D"

    assert CKD.derive(root_key, "M/44'/501'/0'/0/0", curve: :ed25519)
           |> Address.from_xpub() ==
             "4U76rEGDx595M46rWgoA7LwtA821BWCU9CkwG8zbJ6xa"
  end

  test "check if address is valid" do
    valid_address = "4U76rEGDx595M46rWgoA7LwtA821BWCU9CkwG8zbJ6xa"
    assert Address.valid_address?(valid_address) == true
    invalid_address = "ABCDEFG1234567"
    assert Address.valid_address?(invalid_address) == false
  end
end
