defmodule Erebus.KMS.Dummy do
  @behaviour Erebus.KMS

  @moduledoc """
  This is a dummy implementation of the KEK backend. Never use it in production!
  It doesn't take any options.

  ```elixir
  config :my_app, :erebus, kms_backend: Erebus.KMS.Dummy
  ```
  """

  @doc false
  @impl true
  def decrypt(
        %Erebus.EncryptedData{
          encrypted_dek: encrypted_dek,
          handle: _handle,
          version: _version
        },
        _opts
      ) do
    encrypted_dek
    |> Base.decode64!()
  end

  @doc false
  @impl true
  def encrypt(dek, handle, version, _opts) do
    %Erebus.EncryptedData{
      encrypted_dek: dek |> Base.encode64(),
      handle: handle,
      version: version
    }
  end
end
