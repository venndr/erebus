defmodule Erebus.KMS.Dummy do
  @behaviour Erebus.KMS

  @moduledoc """
  This is dummy implementation of KEK backend. Never use it in production!
  It doesn't take anuy options.
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
