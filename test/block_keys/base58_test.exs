defmodule Base58Test do
  use ExUnit.Case

  import BlockKeys.Base58

  doctest BlockKeys.Base58

  test "encode/1" do
    assert encode(0) == ""
    assert encode(57) == "z"
    assert encode(1024) == "Jf"
    assert encode(123_456_789) == "BukQL"
    assert encode(<<1, 0>>) == "5R"
  end

  test "decode/1" do
    assert decode("") == 0
    assert decode("z") == 57
    assert decode("Jf") == 1024
    assert decode("BukQL") == 123_456_789

    assert_raise ArgumentError, fn ->
      decode(123)
    end
  end

  test "correctly encodes" do
    # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert encode_check(
             <<0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E, 0x5E, 0x39,
               0xF8, 0x6A, 0x0D, 0x27, 0x3B, 0xEE>>,
             <<0x00>>
           ) == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
  end

  @test_hex "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"
  @test_base58 "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"

  test "encode_check/2 accepts integer" do
    bin = Base.decode16!(@test_hex, case: :lower)
    integer = :binary.decode_unsigned(bin)
    assert encode_check(integer, 128) == @test_base58
  end

  test "encode_check/2 accepts binary" do
    data_bin = Base.decode16!(@test_hex, case: :lower)
    prefix_bin = :binary.encode_unsigned(128)
    assert encode_check(data_bin, prefix_bin) == @test_base58
  end

  test "encode_check/2 accepts hex" do
    assert encode_check(@test_hex, 128) == @test_base58
    btc_address = "1EUbuiBzfdq939oPArvPGe6sRcUskoYCexXbRk1R6r2hwNdAP2"
    assert encode_check(@test_hex, 0) == btc_address
  end

  test "decode_check/1 accepts hex and returns prefix and payload" do
    {prefix, payload} = decode_check(@test_base58, 37)
    assert Base.encode16(payload, case: :lower) == @test_hex
    assert :binary.decode_unsigned(prefix) == 128
  end

  test "decode_check/1 raises if address too long" do
    assert_raise ArgumentError, fn ->
      decode_check(@test_base58)
    end
  end

  test "decode_check/1 raises if address too short" do
    assert_raise ArgumentError, fn ->
      decode_check("1e")
    end
  end

  test "decode_check/1 raises when checksum doesn't match" do
    assert_raise ArgumentError, fn ->
      decode_check("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jc")
    end
  end

  test "decode_check/1 does not raise for valid address 1" do
    decode_check("1111111111111111111114oLvT2")
  end

  test "decode_check/1 does not raise for valid address 2" do
    decode_check("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i")
  end

  test "decode_check/1 does not raise for valid address 3" do
    decode_check("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
  end

  test "decode_check/1 raises on invalid chars in address" do
    assert_raise ArgumentError, fn ->
      decode_check("0J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
    end
  end
end
