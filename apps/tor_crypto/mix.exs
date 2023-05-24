# SPDX-License-Identifier: ISC

defmodule TorCrypto.MixProject do
  use Mix.Project

  def project do
    [
      app: :tor_crypto,
      version: "0.1.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      licenses: ["ISC"]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:hkdf, "~> 0.2.0"}
    ]
  end
end
