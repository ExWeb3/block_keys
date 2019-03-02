defmodule BlockKeysTest do
  use ExUnit.Case, async: true

  describe "generate/0" do
    test "it generates the mnemonic and root private key" do
      assert %{mnemonic: mnemonic, root_key: root_key} = BlockKeys.generate()
    end
  end
end
