defmodule Erebus.KMS do
  @moduledoc """
  Handle encryption/decryption of secrets via Google CloudKMS.
  """
  alias GoogleApi.CloudKMS.V1.Api.Projects, as: CloudKMSApi

  def decrypt(ciphertext) do
    {:ok, %{plaintext: plaintext}} =
      CloudKMSApi.cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_decrypt(
        connection(),
        System.fetch_env!("GOOGLE_PROJECT"),
        System.fetch_env!("GOOGLE_REGION"),
        System.fetch_env!("GOOGLE_KEYRING"),
        System.fetch_env!("GOOGLE_KEY"),
        System.fetch_env!("GOOGLE_KEY_VERSION"),
        body: %{
          ciphertext: ciphertext
        }
      )

    plaintext |> Base.decode64!()
  end

  def encrypt(plaintext) do
    pem_bin = "PUBLIC_KEY_PATH" |> System.fetch_env!() |> File.read!()
    public_key = :public_key.pem_decode(pem_bin) |> hd() |> :public_key.pem_entry_decode()

    :public_key.encrypt_public(plaintext, public_key,
      rsa_padding: :rsa_pkcs1_oaep_padding,
      rsa_mgf1_md: :sha256,
      rsa_oaep_md: :sha256
    )
    |> Base.encode64()
  end

  defp connection do
    {:ok, token} = Goth.fetch(Yggdrasil.Goth)
    GoogleApi.CloudKMS.V1.Connection.new(token.token)
  end
end
