defmodule MnemonicTest do
  use ExUnit.Case, async: true

  alias BlockKeys.Mnemonic

  describe "phrase_from_entropy" do
    test "it generates entropy given a 24 word mnemonic with correct checksum" do
      expected_phrase =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      entropy =
        <<190, 22, 251, 240, 146, 43, 249, 9, 140, 75, 252, 161, 118, 73, 35, 209, 14, 137, 5, 77,
          231, 112, 145, 240, 175, 51, 70, 244, 156, 246, 101, 254>>

      phrase = Mnemonic.generate_phrase(entropy)

      assert expected_phrase == phrase
    end

    test "incorrect phrase will not cause exception" do
      phrase =
        "sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      assert {:error, "Invalid mnemonic"} == Mnemonic.generate_seed(phrase)
    end
  end

  describe "entropy_from_phrase/1" do
    test "it generates entropy given a 24 word mnemonic with correct checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      entropy = Mnemonic.entropy_from_phrase(mnemonic)

      assert byte_size(entropy) == 32
    end

    test "it returns an error if checksum is not correct" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey able"

      assert {:error, "Checksum is not valid"} = Mnemonic.entropy_from_phrase(mnemonic)
    end
  end

  describe "generate_seed/2" do
    test "it generates seed given a 24 word mnemonic with correct checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "e8006d573be37f252c41d00dcd98a25abbd8ae3a1bdf500922faa6b29777b8a706997cb246587028687fe1fcc001da461f8c0eaa12d04219c1b1b9ad2fc808f1"
    end

    test "it returns an error given a 24 word mnemonic with incorrect checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey able"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end
  end
end
