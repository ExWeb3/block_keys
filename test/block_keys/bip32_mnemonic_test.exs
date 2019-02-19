defmodule Bip32MnemonicTest do
  use ExUnit.Case, async: true

  alias BlockKeys.Bip32Mnemonic

  describe "entropy_from_phrase/1" do
    test "it generates entropy given a 24 word mnemonic with correct checksum" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      entropy = Bip32Mnemonic.entropy_from_phrase(mnemonic)

      assert byte_size(entropy) == 32
    end

    test "it returns an error if checksum is not correct" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey able"

      assert {:error, "Checksum is not valid"} = Bip32Mnemonic.entropy_from_phrase(mnemonic)
    end
  end

  describe "generate_seed/2" do

    test "it generates seed given a 24 word mnemonic with correct checksum" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Bip32Mnemonic.generate_seed(mnemonic)

      assert seed == "e8006d573be37f252c41d00dcd98a25abbd8ae3a1bdf500922faa6b29777b8a706997cb246587028687fe1fcc001da461f8c0eaa12d04219c1b1b9ad2fc808f1"
    end

    test "it returns an error given a 24 word mnemonic with incorrect checksum" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey able"

      assert {:error, "Checksum is not valid"} = Bip32Mnemonic.generate_seed(mnemonic)
    end
  end

  describe "master_keys/1" do
    test "it returns an extended private key and chain code given a seed" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Bip32Mnemonic.generate_seed(mnemonic)

      {private_key, chain_code} = Bip32Mnemonic.master_keys(seed)

      assert private_key == <<48, 166, 181, 156, 204, 201, 36, 252, 159, 253, 74, 176, 140, 92, 1, 240, 214, 164, 4, 103, 151, 187, 37, 93, 137, 25, 235, 62, 149, 192, 136, 113>>

      assert chain_code == <<224, 143, 204, 84, 66, 158, 71, 172, 85, 254, 189, 77, 201, 237, 204, 200, 141, 41, 46, 180, 10, 163, 118, 90, 243, 218, 113, 120,161, 74, 161, 20>>
    end
  end

  describe "master_private_key/1" do
    test "it returns the master private key encoded in Base58check" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Bip32Mnemonic.generate_seed(mnemonic)

      master_private_key = Bip32Mnemonic.master_keys(seed)
                           |> Bip32Mnemonic.master_private_key

      assert master_private_key == "xprv9s21ZrQH143K4J2iCFaJiNoe4UPet96xD6gaVjB5NX3RtpFvKzEpZsKivwLgpPnZ8AiXy1dGoRuH1vp7jgt9KhT2hA2c8qcQX5hnKi36993"
    end
  end

  describe "master_public_key/1" do
    test "it returns an extended public key given a Base58check extended private key" do
      
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Bip32Mnemonic.generate_seed(mnemonic)

      master_private_key = Bip32Mnemonic.master_keys(seed)
                           |> Bip32Mnemonic.master_private_key

      master_public_key = Bip32Mnemonic.master_public_key(master_private_key)

      assert master_public_key == "xpub661MyMwAqRbcGn7BJH7K5WkNcWE9HbpoaKcBJ7agvraQmcb4sXZ57feCnEvDKV37gSV9baYsKvUuRYyD4RKrXt7ciDyKAhLQTbmq5ocYXWZ"
    end
  end
end
