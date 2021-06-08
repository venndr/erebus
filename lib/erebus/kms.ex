defmodule Erebus.KMS do
  @moduledoc """
  This module is a proxy for key backend
  """

  @callback decrypt(Erebus.EncryptedData.t(), Keyword.t()) :: binary

  @callback encrypt(String.t(), String.t(), String.t(), Keyword.t()) :: Erebus.EncryptedData.t()

  @doc """
  Decrypt DEK - provided in form of `Erebus.EncryptedData` struct, using provided backend.
  """
  def decrypt(%Erebus.EncryptedData{} = data, opts) do
    kms_backend = Keyword.fetch!(opts, :kms_backend)
    apply(kms_backend, :decrypt, [data, opts]) |> Base.decode64!()
  end

  @doc """
  Encrypt DEK - returns `Erebus.EncryptedData` struct with encrypted DEK, using given handle, version and backend.
  """
  def encrypt(dek, handle, version, opts) do
    kms_backend = Keyword.fetch!(opts, :kms_backend)
    apply(kms_backend, :encrypt, [dek, handle, version, opts])
  end

  @doc """
  Fetch public key for given handle and version for given KMS backend (if it supports it).
  """
  def get_public_key(handle, version, opts) do
    kms_backend = Keyword.fetch!(opts, :kms_backend)

    if function_exported?(kms_backend, :get_public_key, 3) do
      apply(kms_backend, :get_public_key, [handle, version, opts])
    else
      raise "Provided backend #{kms_backend} does not support fetching public key!"
    end
  end

  @doc """
  Fetch private key for given handle and version for given KMS backend (if it supports it)..
  """
  def get_private_key(handle, version, opts) do
    kms_backend = Keyword.fetch!(opts, :kms_backend)

    if function_exported?(kms_backend, :get_private_key, 3) do
      apply(kms_backend, :get_private_key, [handle, version, opts])
    else
      raise "Provided backend #{kms_backend} does not support fetching private key!"
    end
  end
end
