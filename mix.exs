defmodule Erebus.MixProject do
  use Mix.Project

  def project do
    [
      app: :erebus,
      version: "0.2.5",
      elixir: "~> 1.15.4",
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
      {:goth, "~> 1.4.2"},
      {:google_api_cloud_kms, "~> 0.32.2"},
      {:hackney, "~> 1.17"},
      {:ecto, "~> 3.0", only: :test},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:mock, "~> 0.3.0", only: :test},
      {:jason, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp description(),
    do: """
    Erebus is an implementation of the envelope encryption paradigm, enabling convenient encrypted
    database fields.

    It can use local key files or Google KMS as a key backend, using pluggable and configurable
    modules.
    """

  defp package(),
    do: [
      licenses: ["ISC"],
      links: %{"GitHub" => "https://github.com/venndr/erebus"}
    ]
end
