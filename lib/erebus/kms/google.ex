defmodule Erebus.KMS.Google do
  @behaviour Erebus.KMS

  @request_timeout_ms 1_000
  @default_retry_budget_ms 2_000

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

  Each KMS request (and a Goth token fetch that misses the cache) times out after
  #{@request_timeout_ms}ms, and a transient failure retries until `google_retry_budget_ms`
  (default #{@default_retry_budget_ms}) has passed since the first attempt, so a hung KMS fails a
  call within about #{@request_timeout_ms + @default_retry_budget_ms}ms. Background work that can
  wait longer can pass a larger budget.
  """

  use Retry

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
      call_kms(:decrypt, opts, fn ->
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
      call_kms(:get_public_key, opts, fn ->
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

  # A timeout, transport error, 429 or 5xx retries with jittered backoff: both KMS calls
  # are idempotent. Anything else, or running out of budget, raises Erebus.KMS.Error.
  defguardp is_transient(reason)
            when is_atom(reason) or
                   (is_tuple(reason) and tuple_size(reason) == 2 and elem(reason, 0) == :closed) or
                   (is_map_key(reason, :status) and
                      (:erlang.map_get(:status, reason) == 429 or
                         :erlang.map_get(:status, reason) >= 500))

  defp call_kms(operation, opts, request) do
    retry with: retry_delays(opts),
          atoms: [:transient],
          rescue_only: [] do
      request.() |> classify_result()
    after
      {:ok, result} -> result
      {:error, reason} -> raise_kms_error(operation, reason)
    else
      {:transient, reason} -> raise_kms_error(operation, reason)
    end
  end

  # The deadline is fixed before the first attempt. expiry/2 would start its clock after the
  # first attempt and still make one more once it runs out.
  defp retry_delays(opts) do
    deadline =
      now_ms() + Keyword.get(opts, :google_retry_budget_ms, @default_retry_budget_ms)

    exponential_backoff(100) |> jitter() |> Stream.take_while(&(now_ms() + &1 < deadline))
  end

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp classify_result({:error, reason}) when is_transient(reason), do: {:transient, reason}
  defp classify_result(result), do: result

  defp raise_kms_error(operation, reason),
    do: raise(Erebus.KMS.Error, operation: operation, reason: error_reason(reason))

  defp error_reason(%{status: status}), do: {:http_status, status}
  defp error_reason(reason), do: reason

  defp connection(opts),
    do: opts |> Keyword.fetch!(:google_goth) |> fetch_token() |> connection_from_token()

  # Goth.fetch/2 exits, rather than returning an error, when its token refresh
  # call times out.
  defp fetch_token(goth_name) do
    Goth.fetch(goth_name, @request_timeout_ms)
  catch
    :exit, reason -> {:error, {:exit, reason}}
  end

  # Tesla.Middleware.Timeout bounds the whole request whichever adapter the app configures.
  defp connection_from_token({:ok, token}),
    do:
      Tesla.client([
        {Tesla.Middleware.Timeout, timeout: @request_timeout_ms},
        {Tesla.Middleware.Headers, [{"authorization", "Bearer " <> token.token}]}
      ])

  defp connection_from_token({:error, {:exit, _} = reason}),
    do: raise(Erebus.KMS.Error, operation: :fetch_token, reason: reason)

  # Goth's error message embeds the token endpoint's response body, so keep it out.
  defp connection_from_token({:error, _reason}),
    do: raise(Erebus.KMS.Error, operation: :fetch_token, reason: :token_fetch_failed)
end
