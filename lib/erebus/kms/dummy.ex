defmodule Erebus.KMS.Dummy do
  @behaviour Erebus.KMS

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

  @impl true
  def encrypt(dek, handle, version, _opts) do
    %Erebus.EncryptedData{
      encrypted_dek: dek |> Base.encode64(),
      handle: handle,
      version: version
    }
  end
end
