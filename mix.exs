defmodule Erebus.MixProject do
  use Mix.Project

  def project do
    [
      app: :erebus,
      version: "0.2.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      consolidate_protocols: Mix.env() != :test,
      source_url: "https://github.com/venndr/erebus",
      name: "Erebus",
      description: description(),
      package: package()
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
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:mock, "~> 0.3.0", only: :test},
      {:jason, "~> 1.0"}
    ]
  end

  defp description(),
    do: """
    Erebus is an implementation of the envelope encryption paradigm.
    It allows you to encrypt fields in the database easily.
    It can use local key files or Google KMS as a key backend, using pluggable and configurable modules.
    """

  defp package(),
    do: [
      organization: "venndr",
      links: %{"GitHub" => "https://github.com/venndr/erebus"}
    ]
end
