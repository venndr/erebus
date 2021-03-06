defmodule Erebus.KMS.Google do
  @behaviour Erebus.KMS

  @moduledoc """
  This KMS backend uses Google KMS to encrypt/decrypt DEKs. It requires a 2048 bit RSA key with OAEP
  Padding and SHA256 Digest.

  The used key/service account must have access to the following [KMS roles](https://cloud.google.com/kms/docs/reference/permissions-and-roles#predefined):

  - Cloud KMS CryptoKey Encrypter/Decrypter
  - Cloud KMS CryptoKey Public Key Viewer

  When using this backend, please provide the following options:

  ```elixir
  config :my_app, :erebus,
    kms_backend: Erebus.KMS.Google,
    google_project: "someproject",
    google_region: "someregion",
    google_keyring: "some_keyring",
    google_goth: MyApp.Goth
  ```
  """

  alias GoogleApi.CloudKMS.V1.Api.Projects, as: CloudKMSApi

  @doc false
  @impl true
  def decrypt(
        %Erebus.EncryptedData{
          encrypted_dek: encrypted_dek,
          handle: handle,
          version: version
        },
        opts
      ) do
    google_project = Keyword.fetch!(opts, :google_project)
    google_region = Keyword.fetch!(opts, :google_region)
    google_keyring = Keyword.fetch!(opts, :google_keyring)

    {:ok, %{plaintext: dek}} =
      CloudKMSApi.cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_decrypt(
        connection(opts),
        google_project,
        google_region,
        google_keyring,
        handle,
        version,
        body: %{
          ciphertext: encrypted_dek
        }
      )

    dek |> Base.decode64!()
  end

  @doc false
  @impl true
  def encrypt(dek, handle, version, opts) do
    public_key = Erebus.PublicKeyStore.get_key(handle, version, opts)

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

  @doc false
  def get_public_key(handle, version, opts) do
    google_project = Keyword.fetch!(opts, :google_project)
    google_region = Keyword.fetch!(opts, :google_region)
    google_keyring = Keyword.fetch!(opts, :google_keyring)

    {:ok, %{pem: public_key}} =
      CloudKMSApi.cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(
        connection(opts),
        google_project,
        google_region,
        google_keyring,
        handle,
        version
      )

    public_key
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp connection(opts) do
    goth_name = Keyword.fetch!(opts, :google_goth)

    {:ok, token} = Goth.fetch(goth_name)
    GoogleApi.CloudKMS.V1.Connection.new(token.token)
  end
end
