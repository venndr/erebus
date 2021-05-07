defmodule Erebus.KMS do
  @moduledoc """
  Handle encryption/decryption of secrets via Google CloudKMS.
  """
  alias GoogleApi.CloudKMS.V1.Api.Projects, as: CloudKMSApi

  def decrypt(%Erebus.EncryptedData{
        encrypted_dek: encrypted_dek,
        handle: handle,
        version: version
      }) do
    {:ok, %{plaintext: dek}} =
      CloudKMSApi.cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_decrypt(
        connection(),
        System.fetch_env!("GOOGLE_PROJECT"),
        System.fetch_env!("GOOGLE_REGION"),
        System.fetch_env!("GOOGLE_KEYRING"),
        handle,
        version,
        body: %{
          ciphertext: encrypted_dek
        }
      )

    dek |> Base.decode64!()
  end

  def encrypt(dek, handle, version) do
    public_key = Erebus.PublicKeyStore.get_key(handle, version)

    %Erebus.EncryptedData{
      encrypted_dek:
        :public_key.encrypt_public(dek, public_key,
          rsa_padding: :rsa_pkcs1_oaep_padding,
          rsa_mgf1_md: :sha256,
          rsa_oaep_md: :sha256
        )
        |> Base.encode64(),
      handle: handle,
      version: version
    }
  end

  defp connection do
    {:ok, token} = Goth.fetch(Yggdrasil.Goth)
    GoogleApi.CloudKMS.V1.Connection.new(token.token)
  end

  def get_public_key(handle, version) do
    {:ok, %{pem: public_key}} =
      CloudKMSApi.cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(
        connection(),
        System.fetch_env!("GOOGLE_PROJECT"),
        System.fetch_env!("GOOGLE_REGION"),
        System.fetch_env!("GOOGLE_KEYRING"),
        handle,
        version
      )

    public_key
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end
end
