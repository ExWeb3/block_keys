defmodule WalletTest do
  use ExUnit.Case, async: true

  alias BlockKeys.Wallet

  describe "generate/0" do
    test "it generates the mnemonic and root private key" do
      assert %{ mnemonic: mnemonic, root_key: root_key} = Wallet.generate()
    end
  end
end
