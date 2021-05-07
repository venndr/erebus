defmodule Erebus.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    credentials =
      "GCP_KMS_CREDENTIALS_PATH"
      |> System.fetch_env!()
      |> File.read!()
      |> Jason.decode!()

    # temp

    scopes = ["https://www.googleapis.com/auth/cloudkms"]

    source = {:service_account, credentials, scopes: scopes}

    children = [
      Erebus.PublicKeyStore,
      {Goth, name: Yggdrasil.Goth, source: source}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Erebus.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
