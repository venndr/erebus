defmodule Erebus.MixProject do
  use Mix.Project

  def project do
    [
      app: :erebus,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      consolidate_protocols: Mix.env() != :test
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Erebus.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:goth, "~> 1.3.0-rc.2"},
      {:google_api_cloud_kms, "~> 0.32.2"},
      {:hackney, "~> 1.17"},
      {:ecto, "~> 3.0", only: :test},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
