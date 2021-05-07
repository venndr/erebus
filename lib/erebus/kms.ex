defmodule Erebus.KMS do
  @moduledoc """
  This module is a proxy for key backend
  """

  @callback decrypt(Erebus.EncryptedData.t()) :: binary

  @callback encrypt(String.t(), String.t(), String.t()) :: Erebus.EncryptedData.t()

  @callback get_public_key(String.t(), String.t()) :: term()

  def decrypt(%Erebus.EncryptedData{} = data), do: Erebus.KMS.Google.decrypt(data)

  def encrypt(dek, handle, version), do: Erebus.KMS.Google.encrypt(dek, handle, version)

  def get_public_key(handle, version), do: Erebus.KMS.Google.get_public_key(handle, version)
end
