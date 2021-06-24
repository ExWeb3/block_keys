defmodule BlockKeysTest do
  use ExUnit.Case, async: true

  describe "generate/0" do
    test "it generates the mnemonic and root private key" do
      assert %{mnemonic: _mnemonic, root_key: _root_key} = BlockKeys.generate()
    end

    test "generates mnemonic and root private key for testnet" do
      assert %{mnemonic: _mnemonic, root_key: "tprv" <> _key} = BlockKeys.generate(:testnet)
    end
  end
end
