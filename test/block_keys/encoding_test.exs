defmodule EncodingTest do
  use ExUnit.Case, async: true

  alias BlockKeys.{Encoding, Mnemonic}
  alias BlockKeys.CKD

  describe "decode_extended_key/1" do
    test "it returns a map with all decoded bytes given a base58check private encoded extended key" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      master_private_key = CKD.master_keys(seed)
                           |> CKD.master_private_key
                           |> Encoding.decode_extended_key

      assert master_private_key ==  %{
              chain_code: <<224, 143, 204, 84, 66, 158, 71, 172, 85, 254, 189,
                77, 201, 237, 204, 200, 141, 41, 46, 180, 10, 163, 118, 90, 243,
                218, 113, 120, 161, 74, 161, 20>>,
              depth: <<0>>,
              fingerprint: <<0, 0, 0, 0>>,
              index: <<0, 0, 0, 0>>,
              key: <<0, 48, 166, 181, 156, 204, 201, 36, 252, 159, 253, 74, 176,
                140, 92, 1, 240, 214, 164, 4, 103, 151, 187, 37, 93, 137, 25,
                235, 62, 149, 192, 136, 113>>,
              version_number: <<4, 136, 173, 228>>
      }
    end

    test "it returns a map with all decoded bytes given a base58check public encoded extended key" do
      mnemonic = "safe result wire cattle sauce luggage couple legend pause rather employ pear trigger live daring unlock music lyrics smoke mistake endorse kite obey siren"

      seed = Mnemonic.generate_seed(mnemonic)

      master_private_key = CKD.master_keys(seed)
                           |> CKD.master_private_key

      master_public_key = CKD.master_public_key(master_private_key)
                          |> Encoding.decode_extended_key

      assert master_public_key ==  %{
              chain_code: <<224, 143, 204, 84, 66, 158, 71, 172, 85, 254, 189,
                77, 201, 237, 204, 200, 141, 41, 46, 180, 10, 163, 118, 90, 243,
                218, 113, 120, 161, 74, 161, 20>>,
              depth: <<0>>,
              fingerprint: <<0, 0, 0, 0>>,
              index: <<0, 0, 0, 0>>,
              key: <<3, 128, 40, 86, 6, 23, 133, 88, 180, 217, 74, 146, 146, 5,
                72, 251, 163, 93, 11, 149, 248, 168, 127, 44, 43, 86, 72, 90,
                205, 149, 136, 223, 33>>,
              version_number: <<4, 136, 178, 30>>
      }
    end
  end
end
