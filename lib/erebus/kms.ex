defmodule Erebus.KMS do
  @moduledoc """
  This module is a proxy for key backend
  """

  @callback decrypt(Erebus.EncryptedData.t(), Keyword.t()) :: binary

  @callback encrypt(String.t(), String.t(), String.t(), Keyword.t()) :: Erebus.EncryptedData.t()

  @callback get_public_key(String.t(), String.t(), Keyword.t()) :: term()

  def decrypt(%Erebus.EncryptedData{} = data, opts) do
    kms_backend = Keyword.get(opts, :kms_backend)
    apply(kms_backend, :decrypt, [data, opts]) |> Base.decode64!()
  end

  def encrypt(dek, handle, version, opts) do
    kms_backend = Keyword.get(opts, :kms_backend)
    apply(kms_backend, :encrypt, [dek, handle, version, opts])
  end

  def get_public_key(handle, version, opts) do
    kms_backend = Keyword.get(opts, :kms_backend)
    apply(kms_backend, :get_public_key, [handle, version, opts])
  end
end
