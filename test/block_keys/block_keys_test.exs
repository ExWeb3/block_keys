defmodule BlockKeysTest do
  use ExUnit.Case, async: true

  test "derives extended private key from parent extended private key" do
    path = "m/44'/0'/0'"
    xprv = "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

    assert BlockKeys.derive(xprv, path) == "xprv9y3jSNj99vGEj1FGiDETNSpMAf6K1EJkBXTmqASb6RP5BhiaFqPsfVoWKDAPG4kpGVmxannsEpWh3jLeahq9KoFgPHjwjNDcb3GbqcLCbvZ"
  end

  test "does not derive an extended private key from an extended public key" do
    path = "m/44'/0'/0'"
    xpub = "xpub661MyMwAqRbcGuhqR3C5NZaPT6MufbYsyuvFVW4MTLDXhRtkqMgqZ9cW4uH7fRFEYpkQMR2ze5wwG8dhdopY2z3m2aqnYoi8XtSD6YP6SN7"

    assert BlockKeys.derive(xpub, path) == {:error, "Cannot derive private key from public key"}
  end

  test "derives master public key from master private key" do
    xprv = "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

    assert BlockKeys.xpub(xprv) == "xpub661MyMwAqRbcGuhqR3C5NZaPT6MufbYsyuvFVW4MTLDXhRtkqMgqZ9cW4uH7fRFEYpkQMR2ze5wwG8dhdopY2z3m2aqnYoi8XtSD6YP6SN7"
  end

  test "does not derive master public key from another extended public key" do
    xpub = "xpub661MyMwAqRbcGuhqR3C5NZaPT6MufbYsyuvFVW4MTLDXhRtkqMgqZ9cW4uH7fRFEYpkQMR2ze5wwG8dhdopY2z3m2aqnYoi8XtSD6YP6SN7"

    assert BlockKeys.xpub(xpub) == {:error, "Cannot derive master public key from another extended public key"}
  end

  test "derives xpub from master using BIP44 path" do
    path = "M/44'/0'/0'"
    xprv = "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

    assert BlockKeys.derive(xprv, path) == "xpub6C35qtG2zHpXwVKjpEmTjam5igvoQh2bYkPNdYrCekv44W3ioNi8DJ7zAXTuWgYCbm57ZZRhgiwC56dCYvzfur7pxwKQhcgqga7fafdeH4q"
  end

  test "derivation from hardened path" do
    path = "M/44'/0'/0'"
    xprv = "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"
    xpub = BlockKeys.derive(xprv, path)

    assert BlockKeys.derive(xpub, "M/0/0") == BlockKeys.derive(xprv, "M/44'/0'/0'/0/0")
    assert BlockKeys.derive(xpub, "M/0/1") == BlockKeys.derive(xprv, "M/44'/0'/0'/0/1")
  end
end
