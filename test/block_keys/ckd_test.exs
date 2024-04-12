defmodule CKDTest do
  use ExUnit.Case, async: true

  alias BlockKeys.{CKD, Mnemonic}

  @mersenne_prime 2_147_483_647

  describe "derive/2" do
    test "derives extended private key from parent extended private key" do
      path = "m/44'/0'/0'"

      xprv =
        "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

      assert CKD.derive(xprv, path) ==
               "xprv9y3jSNj99vGEj1FGiDETNSpMAf6K1EJkBXTmqASb6RP5BhiaFqPsfVoWKDAPG4kpGVmxannsEpWh3jLeahq9KoFgPHjwjNDcb3GbqcLCbvZ"
    end

    test "derives extended private keys from testnet parent extended private key" do
      path1 = "m/44'/1'/0'"
      path2 = "m/44'/1'/1'"

      tprv =
        "tprv8ZgxMBicQKsPeCsnrw1DC5P5aAX4Mmfwem2MyRhZwmHemUh6119jfKk5wncqtM32JgqNRNkyUDbr1TKkAmehbhSC9uo6sxMfVnMyBeSjFGc"

      assert CKD.derive(tprv, path1) ==
               "tprv8gAXpcDaWPihJ3YE33cc5Mtpx7pLTkMzLCFiNXdduEJEVEt3ndCZ7MtPuqfbRs1mV4x2AxtfHGv4NdMvQZXVAsZGE869675CqrABLzbmCEy"

      assert CKD.derive(tprv, path2) ==
               "tprv8gAXpcDaWPihJDE4WjMHJsYasDSSnWiPBGrmiWNtjcUHEiapPaDUCU4JDG7YG3PiU5y8LwPQeToXKdkBLGgmLSGsUFrtAeLm2rzBniibRqy"
    end

    test "does not derive an extended private key from an extended public key" do
      path = "m/44'/0'/0'"

      xpub =
        "xpub661MyMwAqRbcGuhqR3C5NZaPT6MufbYsyuvFVW4MTLDXhRtkqMgqZ9cW4uH7fRFEYpkQMR2ze5wwG8dhdopY2z3m2aqnYoi8XtSD6YP6SN7"

      assert CKD.derive(xpub, path) == {:error, "Cannot derive private key from public key"}
    end

    test "does not perform hard derivation from extended public key" do
      path = "M/44'/0'/0'"

      xpub =
        "xpub661MyMwAqRbcGuhqR3C5NZaPT6MufbYsyuvFVW4MTLDXhRtkqMgqZ9cW4uH7fRFEYpkQMR2ze5wwG8dhdopY2z3m2aqnYoi8XtSD6YP6SN7"

      assert CKD.derive(xpub, path) == {:error, "Cannot do hardened derivation from public key"}
    end

    test "derives xpub from master using BIP44 path" do
      path = "M/44'/0'/0'"

      xprv =
        "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

      assert CKD.derive(xprv, path) ==
               "xpub6C35qtG2zHpXwVKjpEmTjam5igvoQh2bYkPNdYrCekv44W3ioNi8DJ7zAXTuWgYCbm57ZZRhgiwC56dCYvzfur7pxwKQhcgqga7fafdeH4q"
    end

    test "derives tpub from master using BIP44 path" do
      path = "M/44'/1'/0'"

      tprv =
        "tprv8ZgxMBicQKsPeqFAcJmHB4cKUSZWWY486KushgCoAfJLSTFuiRR7qSarrxA1iTsQmqGVsivNhpQX4xywgUVijXjNEo2uLz24h2obwLi8AQ2"

      assert CKD.derive(tprv, path) ==
               "tpubDCzSbJ1ENPHFExh8J7DubRgiVcme9JJooA64kkCimb5ndWcppfVkSacvCq3bKhVwT3BYcGc5ogL8nXtCMVbEoU2LNxi4Rp5bGFgYLWaBSsN"
    end

    test "derivation from hardened path" do
      path = "M/44'/0'/0'"

      xprv =
        "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

      xpub = CKD.derive(xprv, path)

      assert CKD.derive(xpub, "M/0/0") == CKD.derive(xprv, "M/44'/0'/0'/0/0")
      assert CKD.derive(xpub, "M/0/1") == CKD.derive(xprv, "M/44'/0'/0'/0/1")
    end

    test "derives xpub from master with network keyword" do
      path = "M/44'/0'/0'"

      xprv =
        "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

      assert CKD.derive(xprv, path, network: :solana) ==
               "xpubDeb7pPtgAGEq2eo7ZHPNUvR7xsF4nhK5dBRqA1KD9jZSkSouoZQj6XJ2BVMAMkjHyPeUtUv46Ku4WCWns9uZnUc9BbV5WvFaWNeXbn15bKXNzr"
    end
  end

  describe "master_keys/1" do
    test "it returns an extended private key and chain code given a seed" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      {private_key, chain_code} = CKD.master_keys(seed)

      assert private_key ==
               <<48, 166, 181, 156, 204, 201, 36, 252, 159, 253, 74, 176, 140, 92, 1, 240, 214,
                 164, 4, 103, 151, 187, 37, 93, 137, 25, 235, 62, 149, 192, 136, 113>>

      assert chain_code ==
               <<224, 143, 204, 84, 66, 158, 71, 172, 85, 254, 189, 77, 201, 237, 204, 200, 141,
                 41, 46, 180, 10, 163, 118, 90, 243, 218, 113, 120, 161, 74, 161, 20>>
    end
  end

  describe "master_private_key/1" do
    test "it returns the master private key encoded in Base58check" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      master_private_key =
        CKD.master_keys(seed)
        |> CKD.master_private_key()

      assert master_private_key ==
               "xprv9s21ZrQH143K4J2iCFaJiNoe4UPet96xD6gaVjB5NX3RtpFvKzEpZsKivwLgpPnZ8AiXy1dGoRuH1vp7jgt9KhT2hA2c8qcQX5hnKi36993"
    end

    test "returns proper seed and master private key for mainnet and testnet" do
      mnemonic =
        "roof frost neutral divide pool item north novel swim undo true blur just goddess myself orient correct zebra clarify shuffle child faculty artefact achieve"

      seed = Mnemonic.generate_seed(mnemonic)

      assert seed ==
               "26f53f7dd6f98ac389aa77da10b796d9464b263a93ca1aadf1923f55e74bff28a69b07bb5eff1d37db8a823ec7e29f6697e7b1ad21febac0f8adb4f2807b4691"

      mainnet_private_key = CKD.master_keys(seed) |> CKD.master_private_key(:mainnet)

      assert mainnet_private_key ==
               "xprv9s21ZrQH143K2g6KiEEp5wBk56AwvztNib5kywYz1zxedRZfsmJqS1BU8xoq769ogFjTitLt4MG3QvRR8vgQnKNzvNx9WD9jK4irkaqB7Na"

      testnet_private_key = CKD.master_keys(seed) |> CKD.master_private_key(:testnet)

      assert testnet_private_key ==
               "tprv8ZgxMBicQKsPdVKrNo6KFaojPDbAAWvP48zsrMySVyT8R2Jks8eawkYv48yV7TY83hGEiyxeDhqqsmyAG92MbNebT2ATAZsnEAUHCBLpvrA"
    end
  end

  describe "master_public_key/1" do
    test "it returns an extended public key given a Base58check extended private key" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      master_private_key =
        CKD.master_keys(seed)
        |> CKD.master_private_key()

      master_public_key = CKD.master_public_key(master_private_key)

      assert master_public_key ==
               "xpub661MyMwAqRbcGn7BJH7K5WkNcWE9HbpoaKcBJ7agvraQmcb4sXZ57feCnEvDKV37gSV9baYsKvUuRYyD4RKrXt7ciDyKAhLQTbmq5ocYXWZ"
    end

    test "returns proper public key for mainnet and testnet" do
      mainnet_private_key =
        "xprv9tyUQV64JT5qs3RSTJkXCWKMyUgoQp7F3hA1xzG6ZGu6u6Q9VMNjGr67Lctvy5P8oyaYAL9CAWrUE9i6GoNMKUga5biW6Hx4tws2six3b9c"

      mainnet_public_key = CKD.master_public_key(mainnet_private_key)

      assert mainnet_public_key ==
               "xpub67xpozcx8pe95XVuZLHXZeG6XWXHpGq6Qv5cmNfi7cS5mtjJ2tgypeQbBs2UAR6KECeeMVKZBPLrtJunSDMstweyLXhRgPxdp14sk9tJPW9"

      testnet_private_key =
        "tprv8ZgxMBicQKsPdmnHBwtQtqiqL6PYEVehtGeXA53UoJEaaLpbhYgn7JEzHhuXusKgYiNyZnC71oS5D7s1CDVmsMpoRxfM5e3TZfG9LAbmyuc"

      testnet_public_key = CKD.master_public_key(testnet_private_key)

      assert testnet_public_key ==
               "tpubD6NzVbkrYhZ4XEp55bZ1JFNwu7uUPpqcTaFJSb5nDa2yQq5NKwWNHnrrTrGkK1HxcfswjNaMY1fYx23rohEt6PwKqX8HAeFHTb8oYhXsaYi"
    end

    test "returns proper public key with network keyword" do
      mainnet_private_key =
        "xprv9tyUQV64JT5qs3RSTJkXCWKMyUgoQp7F3hA1xzG6ZGu6u6Q9VMNjGr67Lctvy5P8oyaYAL9CAWrUE9i6GoNMKUga5biW6Hx4tws2six3b9c"

      mainnet_public_key = CKD.master_public_key(mainnet_private_key, network: :solana)

      assert mainnet_public_key ==
               "xpubDeb7pNy9ZrJfKYBgSVfGXtVfeJWFPmkZoxhMFwAf1YC34mH74pyFja1T1pu1xHiWSBoCMyKa41TTvd821mnV5D1rom5JzN6KPPiqnaoK6L6Jwn"

      testnet_private_key =
        "tprv8ZgxMBicQKsPdmnHBwtQtqiqL6PYEVehtGeXA53UoJEaaLpbhYgn7JEzHhuXusKgYiNyZnC71oS5D7s1CDVmsMpoRxfM5e3TZfG9LAbmyuc"

      testnet_public_key = CKD.master_public_key(testnet_private_key, network: :solana)

      assert testnet_public_key ==
               "tpubCk2VbTbSG6A2iAeAru4sKG5Xt2u6eBdMhy9kNt2t5SPqJoTGxF4i5kANbAV4WoQ8Fi7m5oQVMd3TD3novoKLtquy8XKmbe45pMm8WbSRpKgddt"
    end
  end

  describe "child_key_public/2" do
    test "it returns the base58 encoded child extended public key given parent extended key and index" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      master_private_key =
        CKD.master_keys(seed)
        |> CKD.master_private_key()

      master_public_key = CKD.master_public_key(master_private_key)

      child_extended_public_key = CKD.child_key_public(master_public_key, 0)

      assert child_extended_public_key ==
               "xpub686qTu6J49gBYxxSMhXKe9v7h8eBf7uKdDNVrfa5nBhHS7SNqi4kcCwsX8VvirP3yp8eiw3X8a6v1MAzBNTzeiuhVgTgptPLi4C9whoB5Qg"
    end
  end

  describe "child_key_private/2" do
    test "it returns the base58 encoded child extended public key given parent extended key and index" do
      mnemonic =
        "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      master_private_key =
        CKD.master_keys(seed)
        |> CKD.master_private_key()

      child_extended_private_key = CKD.child_key_private(master_private_key, 0)

      assert child_extended_private_key ==
               "xprv9u7V4PZQDn7tLUsyFfzKH1yP96ohFfBUFzSu4HAUDrAJZK7EJAkW4QdPftAnA6t3SauQvxBmMMbYb8YXYgFuyxEVaQ5tZYD74zkfZu4AuZF"
    end

    test "it returns the base58 encoded child extended public key with curve order padded to 32 bytes" do
      mnemonic =
        "jump essence frog wait sponsor lawsuit fringe alcohol assume bar over stick sponsor tube clerk vessel release jelly among century post century meat taxi"

      seed = Mnemonic.generate_seed(mnemonic)

      master_private_key =
        CKD.master_keys(seed)
        |> CKD.master_private_key()

      child_extended_private_key =
        master_private_key
        |> CKD.child_key_private(44 + 1 + @mersenne_prime)
        |> CKD.child_key_private(60 + 1 + @mersenne_prime)
        |> CKD.child_key_private(0 + 1 + @mersenne_prime)

      assert child_extended_private_key ==
               "xprv9ynLSPkhcQzGW7R2jq1TLBPf6wRZvaS7kp9ieXMr5d7i1GPitnNn76yqzGFMqSQMmNaSvzxRTDbavJt5jACSL1bkta5yF4mzhz5P7Bgov3x"
    end
  end
end
