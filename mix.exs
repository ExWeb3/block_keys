defmodule BlockKeys.MixProject do
  use Mix.Project

  def project do
    [
      app: :block_keys,
      version: "0.1.0",
      elixir: "~> 1.7",
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

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:secure_random, "~> 0.5"},
      {:libsecp256k1, "~> 0.1.9"}
    ]
  end
end
