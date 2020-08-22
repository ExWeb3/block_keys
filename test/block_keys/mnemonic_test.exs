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

    test "it generates a phrase given 8 bytes of entropy" do
      expected_phrase = "actual suspect project family abuse hover"

      entropy_hex = "02fb5ab0294012dc"
      entropy_bytes = Base.decode16!(entropy_hex, case: :lower)

      phrase = Mnemonic.generate_phrase(entropy_bytes)

      assert expected_phrase == phrase
      assert entropy_hex == Mnemonic.entropy_from_phrase(phrase)
    end

    test "it generates a phrase given 12 bytes of entropy" do
      expected_phrase = "transfer bike budget spend upset crime fish jump exercise"

      entropy_hex = "e722c47668aef26715ebc74f"
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

    test "incorrect phrase will not cause exception" do
      phrase =
        "sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      assert {:error, "Invalid mnemonic"} == Mnemonic.generate_seed(phrase)
    end
  end

  describe "entropy_from_phrase/1" do
    test "it generates entropy given a 3 word mnemonic" do
      mnemonic = "lawsuit orbit nut"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "7e337e5e"
    end

    test "it generates entropy given a 6 word mnemonic" do
      mnemonic = "fury ball candy suit joy supreme"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "5e623c856c8789b3"
    end

    test "it generates entropy given a 9 word mnemonic" do
      mnemonic = "table heart refuse trim ozone essay grit purchase hover"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "dced4ad1f459e89a59ad716e"
    end

    test "it generates entropy given a 12 word mnemonic with correct checksum" do
      mnemonic = "assault tank plastic awful speed tool little today glance chief notice dance"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "0d9bb698085d11c960a71a62a4fa5b9b"
    end

    test "it generates entropy given a 15 word mnemonic with correct checksum" do
      mnemonic =
        "version aware laptop milk kangaroo betray gossip slab ugly copy hospital chimney index fiber carbon"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "f2c209f44647982ad93e57ec0601b794072cab48"
    end

    test "it generates entropy given a 18 word mnemonic with correct checksum" do
      mnemonic =
        "morning mercy address trend rebuild expect fabric legend swarm imitate emerge fluid village any oyster bright gain stadium"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "8ff1680df40b34a0945bfcdb6e2d22acdf40146798e05eda"
    end

    test "it generates entropy given a 21 word mnemonic with correct checksum" do
      mnemonic =
        "mango cup crew drift town oyster city measure stairs repair theory group throw this salute virtual health fox river leisure coil"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "8726b4cd216e653cca5c4fd456d381337e15c1afb7a36a2b8aeb3fd2"
    end

    test "it generates entropy given a 24 word mnemonic with correct checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      assert Mnemonic.entropy_from_phrase(mnemonic) ==
               "be16fbf0922bf9098c4bfca1764923d10e89054de77091f0af3346f49cf665fe"
    end

    test "it returns an error if checksum is not correct" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey able"

      assert {:error, "Checksum is not valid"} = Mnemonic.entropy_from_phrase(mnemonic)
    end
  end

  describe "generate_seed/2" do
    test "it generates seed given a 3 word mnemonic" do
      mnemonic = "grab naive furnace"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "a55601e89ec1296be238d8525b7dcc1e0a9a7740d365c9b8592264aa87b6f6335388f42cac49ebbd743a93adcd43c2d7fb7eb43de1963a9e325cbd938ba737f1"
    end

    test "it generates seed given a 6 word mnemonic" do
      mnemonic = "humble shallow omit conduct wonder armed"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "34c26a6eab060af41ae6b2f300ab1a79c52fedbb4d69f82bc81772664796ed88c3899ec58b7bc8c929926e02fb99250624c2b56908f00c9585ed493334cf0c2f"
    end

    test "it generates seed given a 9 word mnemonic" do
      mnemonic = "census across motion horn gain siren battle pair taxi"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "10baf276e94b01b9bf71501cd5af9e3b1dcbbd66ee458f6beaf761354519753c6a1a30e53b976a2fa2986a64130ce0f2ca5a25f7b15b5518eb691cde3f450f40"
    end

    test "it generates seed given a 12 word mnemonic with correct checksum" do
      mnemonic = "demise elevator first honey olympic flee ankle sure cube chaos kiss tray"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "bf99a6cb6658e0e5a483eca7fab81a2090031dd49d199e71975d2d3422df5496e8f1b48382d2fbc6a9bb8128bbcbbab4d092445fc5152aa2be08744ac6dc31cc"
    end

    test "it generates seed given a 15 word mnemonic with correct checksum" do
      mnemonic =
        "vanish rocket toss pudding improve seed print cup into easy easily make accuse festival accuse"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "77eef374f9d4ab1ace93c889796bb60bca27da1b212ffc8c705d05ca4e52bb9211079f716df4e71386d89039717d440d68e78e51aab9350b41465c98ede9e996"
    end

    test "it generates seed given a 18 word mnemonic with correct checksum" do
      mnemonic =
        "century dentist arrest prison absent marine wet quality possible gap raise sand early pottery wild logic dwarf sleep"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "80c6264cc7e99ad0ee91e4c5ce665b04a9525cdec4ed29e00c9854fdcf42685257971813b86a761a4a97e744bfa111fc04afcdcb336070bea4abf9c94b9ff5d6"
    end

    test "it generates seed given a 21 word mnemonic with correct checksum" do
      mnemonic =
        "surface deal typical traffic audit empower labor ozone snack absent dad warrior laugh salt album latin club add film feel fragile"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "75a17298707d89f35bbce9b35e8ce7745ba9f11d4310c7b6edf9e10cf97eb87b405413a8fad0c2b0acd3c518fa2aa923b682bfe3579c1865b535051ac3921a8f"
    end

    test "it generates seed given a 24 word mnemonic with correct checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "e8006d573be37f252c41d00dcd98a25abbd8ae3a1bdf500922faa6b29777b8a706997cb246587028687fe1fcc001da461f8c0eaa12d04219c1b1b9ad2fc808f1"
    end

    test "it returns an error given a 3 word mnemonic with incorrect checksum" do
      mnemonic = "safe result wire"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end

    test "it returns an error given a 6 word mnemonic with incorrect checksum" do
      mnemonic = "safe result wire cattle sauce luggage"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end

    test "it returns an error given a 9 word mnemonic with incorrect checksum" do
      mnemonic = "safe result wire cattle sauce luggage couple legend prize"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end

    test "it returns an error given a 12 word mnemonic with incorrect checksum" do
      mnemonic =
        "jungle random consider parade arctic window often asthma flush morning wood safe"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end

    test "it returns an error given a 15 word mnemonic with incorrect checksum" do
      mnemonic =
        "cross canyon render bundle flip sleep alone orchard easily dolphin agree habit frog idle flush"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end

    test "it returns an error given a 18 word mnemonic with incorrect checksum" do
      mnemonic =
        "derive toss surge cart first clap ketchup gadget benefit snow peasant frost rotate champion foster lava cross habit"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end

    test "it returns an error given a 21 word mnemonic with incorrect checksum" do
      mnemonic =
        "library useless kangaroo wrestle material material hood payment essay swear finish cable zoo agree world private tree aspect midnight remain cross"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end

    test "it returns an error given a 24 word mnemonic with incorrect checksum" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey able"

      assert {:error, "Checksum is not valid"} = Mnemonic.generate_seed(mnemonic)
    end
  end
end
