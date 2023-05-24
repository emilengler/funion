# SPDX-License-Identifier: ISC

defmodule TorProto.MixProject do
  use Mix.Project

  def project do
    [
      app: :tor_proto,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      licenses: ["ISC"]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :ssl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:tor_cell, in_umbrella: true},
      {:tor_crypto, in_umbrella: true},
      {:tor_dir, in_umbrella: true}
    ]
  end
end
