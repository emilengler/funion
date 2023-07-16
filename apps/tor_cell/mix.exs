# SPDX-License-Identifier: ISC

defmodule TorCell.MixProject do
  use Mix.Project

  def project do
    [
      app: :tor_cell,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      license: ["ISC"]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:tor_cert, in_umbrella: true},
      {:tor_crypto, in_umbrella: true}
    ]
  end
end
