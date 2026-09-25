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

    %{plaintext: dek} =
      call_kms(:decrypt, fn ->
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
      end)

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

    %{pem: public_key} =
      call_kms(:get_public_key, fn ->
        CloudKMSApi.cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(
          connection(opts),
          google_project,
          google_region,
          google_keyring,
          handle,
          version
        )
      end)

    public_key
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  # A timeout, transport error, 429 or 5xx gets one retry: both KMS calls are
  # idempotent. Anything else, or a second failure, raises Erebus.KMS.Error.
  defguardp is_transient(reason)
            when is_atom(reason) or
                   (is_tuple(reason) and tuple_size(reason) == 2 and elem(reason, 0) == :closed) or
                   (is_map_key(reason, :status) and
                      (:erlang.map_get(:status, reason) == 429 or
                         :erlang.map_get(:status, reason) >= 500))

  defp call_kms(operation, request), do: request.() |> kms_result(operation, request)

  defp kms_result({:ok, result}, _operation, _retry), do: result

  defp kms_result({:error, reason}, operation, nil), do: raise_kms_error(operation, reason)

  defp kms_result({:error, reason}, operation, retry) when is_transient(reason),
    do: retry.() |> kms_result(operation, nil)

  defp kms_result({:error, reason}, operation, _retry), do: raise_kms_error(operation, reason)

  defp raise_kms_error(operation, reason),
    do: raise(Erebus.KMS.Error, operation: operation, reason: error_reason(reason))

  defp error_reason(%{status: status}), do: {:http_status, status}
  defp error_reason(reason), do: reason

  defp connection(opts),
    do: opts |> Keyword.fetch!(:google_goth) |> fetch_token() |> connection_from_token()

  # Goth.fetch/1 exits, rather than returning an error, when its token refresh
  # call times out.
  defp fetch_token(goth_name) do
    Goth.fetch(goth_name)
  catch
    :exit, reason -> {:error, {:exit, reason}}
  end

  defp connection_from_token({:ok, token}), do: GoogleApi.CloudKMS.V1.Connection.new(token.token)

  defp connection_from_token({:error, reason}),
    do: raise(Erebus.KMS.Error, operation: :fetch_token, reason: reason)
end
