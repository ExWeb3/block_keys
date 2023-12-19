defmodule BlockKeys.MixProject do
  use Mix.Project

  def project do
    [
      app: :block_keys,
      version: "1.0.1",
      elixir: "~> 1.7",
      description: description(),
      start_permanent: Mix.env() == :prod,
      source_url: "https://github.com/agilealpha/block_keys",
      package: %{
        name: "block_keys",
        licenses: ["Apache License 2.0"],
        links: %{"GitHub" => "https://github.com/AgileAlpha/block_keys"}
      },
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],
      name: "BlockKeys",
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp description do
    "This package generates Hierarchical Deterministic blockchain wallets for multiple currencies."
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:ex_keccak, "~> 0.7.3"},
      {:ex_secp256k1, "~> 0.7.2"},
      {:excoveralls, "~> 0.10", only: :test}
    ]
  end
end
