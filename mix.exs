defmodule BlockKeys.MixProject do
  use Mix.Project

  def project do
    [
      app: :block_keys,
      version: "0.1.0",
      elixir: "~> 1.7",
      description: description(),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp description do
    "This package generates Hierarchical Deterministic blockchain wallets for multiple currencies."
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:secure_random, "~> 0.5"},
      {:libsecp256k1, "~> 0.1.9"},
      {:keccakf1600, "~> 2.0", hex: :keccakf1600_orig},
      {:base58check, github: "tzumby/base58check"}
    ]
  end
end
