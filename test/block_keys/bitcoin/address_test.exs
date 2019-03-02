defmodule AddressTest do
  use ExUnit.Case, async: true

  alias BlockKeys.Bitcoin.Address
  alias BlockKeys.CKD

  test "generate address from public key" do
    xpub =
      "xpub6C35qtG2zHpXwVKjpEmTjam5igvoQh2bYkPNdYrCekv44W3ioNi8DJ7zAXTuWgYCbm57ZZRhgiwC56dCYvzfur7pxwKQhcgqga7fafdeH4q"

    assert Address.from_xpub(xpub) == "1G2WGDknNjKDArLZTxwvbF3ftD8dR6o5nS"
  end

  test "generates the first address for BIP44 path" do
    path = "M/44'/0'/0'/0/0"

    xprv =
      "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

    xpub = CKD.derive(xprv, path)

    assert Address.from_xpub(xpub) == "15HJfZhj5V9qQeyvFxPxMWNzRbcZpFUAaA"
  end
end
