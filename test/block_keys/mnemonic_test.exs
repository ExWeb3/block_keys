defmodule MnemonicTest do
  use ExUnit.Case, async: true

  alias BlockKeys.Mnemonic

  describe "phrase_from_entropy" do
    test "it generates a phrase given 32 bytes of entropy" do
      expected_phrase =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      entropy_hex = "be16fbf0922bf9098c4bfca1764923d10e89054de77091f0af3346f49cf665fe"
      entropy_bytes = Base.decode16!(entropy_hex, case: :lower)

      phrase = Mnemonic.generate_phrase(entropy_bytes)

      assert expected_phrase == phrase
      assert entropy_hex == Mnemonic.entropy_from_phrase(phrase)
    end

    test "it generates a phrase given 16 bytes of entropy" do
      expected_phrase =
        "they air shoot swim divide brief castle little fever size original fiscal"

      entropy_hex = "e080af1a6df3fe37c8e41455793e72ab"
      entropy_bytes = Base.decode16!(entropy_hex, case: :lower)

      phrase = Mnemonic.generate_phrase(entropy_bytes)

      assert expected_phrase == phrase
      assert entropy_hex == Mnemonic.entropy_from_phrase(phrase)
    end

    test "it generates a phrase given 4 bytes of entropy" do
      expected_phrase = "elite edit very"

      entropy_hex = "4808cfcb"
      entropy_bytes = Base.decode16!(entropy_hex, case: :lower)

      phrase = Mnemonic.generate_phrase(entropy_bytes)

      assert expected_phrase == phrase
      assert entropy_hex == Mnemonic.entropy_from_phrase(phrase)
    end
  end

  describe "entropy_from_phrase/1" do
    test "it generates entropy given a 24 word mnemonic with correct checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "be16fbf0922bf9098c4bfca1764923d10e89054de77091f0af3346f49cf665fe"
    end

    test "it generates entropy given a 12 word mnemonic with correct checksum" do
      mnemonic = "assault tank plastic awful speed tool little today glance chief notice dance"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "0d9bb698085d11c960a71a62a4fa5b9b"
    end

    test "it generates entropy given a 3 word mnemonic" do
      mnemonic = "lawsuit orbit nut"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "7e337e5e"
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

    test "it generates seed given a 12 word mnemonic with correct checksum" do
      mnemonic = "demise elevator first honey olympic flee ankle sure cube chaos kiss tray"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "bf99a6cb6658e0e5a483eca7fab81a2090031dd49d199e71975d2d3422df5496e8f1b48382d2fbc6a9bb8128bbcbbab4d092445fc5152aa2be08744ac6dc31cc"
    end

    test "it generates seed given a 3 word mnemonic" do
      mnemonic = "grab naive furnace"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "a55601e89ec1296be238d8525b7dcc1e0a9a7740d365c9b8592264aa87b6f6335388f42cac49ebbd743a93adcd43c2d7fb7eb43de1963a9e325cbd938ba737f1"
    end

    test "it returns an error given a 24 word mnemonic with incorrect checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey able"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end
  end
end
