defmodule Erebus.GoogleTest do
  use ExUnit.Case, async: false

  import Mock
  import Retry.DelayStreams

  # A Tesla adapter standing in for the KMS HTTP API: each request takes the next scripted
  # reply, and the last one repeats. :ok echoes the ciphertext back as the plaintext.
  defmodule ScriptedKMS do
    @moduledoc false

    use Agent

    def start_link(replies), do: Agent.start_link(fn -> {0, replies} end, name: __MODULE__)

    def call(env, _opts),
      do: __MODULE__ |> Agent.get_and_update(&next_reply/1) |> reply(env)

    defp next_reply({calls, [last]}), do: {last, {calls + 1, [last]}}
    defp next_reply({calls, [next | rest]}), do: {next, {calls + 1, rest}}

    defp reply(:ok, env) do
      %{"ciphertext" => ciphertext} = Jason.decode!(env.body)
      {:ok, %{env | status: 200, body: Jason.encode!(%{plaintext: ciphertext})}}
    end

    defp reply({:status, status}, env), do: {:ok, %{env | status: status, body: "{}"}}
    defp reply(:hang, _env), do: Process.sleep(:infinity)
    defp reply({:error, _reason} = error, _env), do: error
  end

  @rsa_public_key {:RSAPublicKey,
                   27_693_458_449_514_005_222_579_440_529_993_482_038_946_075_475_126_655_403_459_101_233_604_394_388_555_678_223_244_748_993_421_634_951_931_300_701_592_769_551_385_962_049_809_028_125_449_319_213_828_156_739_168_214_627_552_688_542_334_360_858_081_843_226_816_359_579_957_072_638_368_190_673_281_234_544_078_217_741_722_742_698_741_649_295_809_169_546_596_216_802_714_885_351_646_574_695_180_861_543_941_437_174_435_871_314_365_772_980_187_033_270_141_469_132_000_832_828_069_180_839_247_679_111_093_016_731_409_671_500_045_321_985_733_852_823_010_254_402_341_504_868_837_341_207_068_888_009_898_746_896_946_820_792_024_443_556_725_798_964_238_912_904_692_223_915_333_954_752_360_168_238_163_616_076_180_423_433_528_337_493_228_935_239_636_301_761_302_761_299_003_705_743_189_136_352_628_689_805_067_275_140_023_762_421_151,
                   65_537}

  test "decrypt" do
    with_mocks [
      {GoogleApi.CloudKMS.V1.Api.Projects, [],
       [
         cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_decrypt:
           fn _,
              _,
              _,
              _,
              _,
              _,
              body: %{
                ciphertext: encrypted_dek
              } ->
             {:ok, %{plaintext: encrypted_dek}}
           end
       ]},
      {Goth, [], [fetch: fn _, _ -> {:ok, %{token: "token"}} end]}
    ] do
      assert "hellothere" ==
               Erebus.KMS.Google.decrypt(
                 %Erebus.EncryptedData{
                   encrypted_dek: Base.encode64("hellothere"),
                   handle: "x",
                   version: "y"
                 },
                 google_project: "someproject",
                 google_region: "someregion",
                 google_keyring: "somekeyring",
                 google_goth: :not_existing
               )
    end
  end

  test "get_public_key" do
    public_key = read_fixture(["handle", "1", "public.pem"])

    with_mocks [
      {GoogleApi.CloudKMS.V1.Api.Projects, [],
       [
         cloudkms_projects_locations_key_rings_crypto_keys_crypto_key_versions_get_public_key:
           fn _, _, _, _, _, _ ->
             {:ok, %{pem: public_key}}
           end
       ]},
      {Goth, [], [fetch: fn _, _ -> {:ok, %{token: "token"}} end]}
    ] do
      assert @rsa_public_key ==
               Erebus.KMS.Google.get_public_key(
                 "x",
                 "v",
                 google_project: "someproject",
                 google_region: "someregion",
                 google_keyring: "somekeyring",
                 google_goth: :not_existing
               )
    end
  end

  test "encrypt" do
    with_mock Erebus.PublicKeyStore, get_key: fn _, _, _ -> @rsa_public_key end do
      encrypted_data =
        Erebus.KMS.Google.encrypt(
          "dek",
          "handle",
          "version",
          []
        )

      assert Erebus.EncryptedData == encrypted_data.__struct__
      assert not is_nil(encrypted_data.encrypted_dek)
      assert "handle" == encrypted_data.handle
      assert "version" == encrypted_data.version
    end
  end

  describe "decrypt when KMS fails" do
    setup_with_mocks([{Goth, [], [fetch: fn _, _ -> {:ok, %{token: "token"}} end]}]) do
      :ok
    end

    test "retries a timeout and returns the DEK" do
      script_kms([{:error, :timeout}, :ok])

      assert "hellothere" == Erebus.KMS.Google.decrypt(encrypted("hellothere"), google_opts())
      assert kms_calls() == 2
    end

    test "retries a 5xx and returns the DEK" do
      script_kms([{:status, 503}, :ok])

      assert "hellothere" == Erebus.KMS.Google.decrypt(encrypted("hellothere"), google_opts())
      assert kms_calls() == 2
    end

    test "raises without retrying a non-transient HTTP error" do
      script_kms([{:status, 403}])

      assert_raise Erebus.KMS.Error, "KMS decrypt failed: {:http_status, 403}", fn ->
        Erebus.KMS.Google.decrypt(encrypted("hellothere"), google_opts())
      end

      assert kms_calls() == 1
    end

    test "treats a nil budget or request timeout as the default" do
      script_kms([{:error, :timeout}, :ok])
      opts = google_opts(google_retry_budget_ms: nil, google_request_timeout_ms: nil)

      assert "hellothere" == Erebus.KMS.Google.decrypt(encrypted("hellothere"), opts)
      assert_called(Goth.fetch(:_, 1_000))
    end

    test "retries until the caller's retry budget runs out, then raises" do
      script_kms([{:error, :timeout}])
      opts = google_opts(google_retry_budget_ms: 500)

      elapsed_us = time_decrypt_timeout(opts)

      assert kms_calls() > 1
      assert elapsed_us < 2_000_000
    end

    test "does not start a retry that would begin after the budget" do
      # Seeded so jitter's first delay is 100ms: after the first 100ms attempt, a retry would
      # start at about 200ms, past the 150ms budget.
      :rand.seed(:exsss, {9, 9, 9})
      assert exponential_backoff(100) |> jitter() |> Enum.at(0) == 100
      :rand.seed(:exsss, {9, 9, 9})
      script_kms([:hang])

      opts =
        google_opts(google_retry_budget_ms: 150, google_request_timeout_ms: 100)

      time_decrypt_timeout(opts)

      assert kms_calls() == 1
    end

    test "honours a caller's request timeout" do
      script_kms([:hang])
      opts = google_opts(google_retry_budget_ms: 0, google_request_timeout_ms: 100)

      elapsed_us = time_decrypt_timeout(opts)

      assert elapsed_us < 900_000
      assert_called(Goth.fetch(:_, 100))
    end

    @tag timeout: 5_000
    test "gives up on a hung KMS request after one second" do
      script_kms([:hang])
      opts = google_opts(google_retry_budget_ms: 0)

      elapsed_us = time_decrypt_timeout(opts)

      assert elapsed_us in 1_000_000..2_000_000
      assert_called(Goth.fetch(:_, 1_000))
    end
  end

  describe "decrypt when the Goth token fetch fails" do
    test "raises Erebus.KMS.Error when the fetch exits" do
      with_mock Goth, fetch: fn _, _ -> exit({:timeout, {GenServer, :call, []}}) end do
        assert_raise Erebus.KMS.Error, ~r/KMS fetch_token failed/, fn ->
          Erebus.KMS.Google.decrypt(encrypted("hellothere"), google_opts())
        end
      end
    end

    test "raises Erebus.KMS.Error without the token response body" do
      error = %RuntimeError{
        message: "unexpected status 400 from Google\n{\"error\":\"invalid_grant\"}"
      }

      with_mock Goth, fetch: fn _, _ -> {:error, error} end do
        assert_raise Erebus.KMS.Error, "KMS fetch_token failed: :token_fetch_failed", fn ->
          Erebus.KMS.Google.decrypt(encrypted("hellothere"), google_opts())
        end
      end
    end
  end

  defp script_kms(replies) do
    Application.put_env(:tesla, GoogleApi.CloudKMS.V1.Connection, adapter: ScriptedKMS)
    on_exit(fn -> Application.delete_env(:tesla, GoogleApi.CloudKMS.V1.Connection) end)
    start_supervised!({ScriptedKMS, replies})
  end

  defp kms_calls, do: Agent.get(ScriptedKMS, &elem(&1, 0))

  # Asserts decrypt raises the KMS timeout error and returns how long it took, in µs.
  defp time_decrypt_timeout(opts) do
    {elapsed_us, _} =
      :timer.tc(fn ->
        assert_raise Erebus.KMS.Error, "KMS decrypt failed: :timeout", fn ->
          Erebus.KMS.Google.decrypt(encrypted("hellothere"), opts)
        end
      end)

    elapsed_us
  end

  defp encrypted(dek),
    do: %Erebus.EncryptedData{encrypted_dek: Base.encode64(dek), handle: "x", version: "y"}

  defp google_opts(overrides \\ []),
    do:
      Keyword.merge(
        [
          google_project: "someproject",
          google_region: "someregion",
          google_keyring: "somekeyring",
          google_goth: :not_existing
        ],
        overrides
      )

  defp read_fixture(path_segments),
    do:
      [__ENV__.file, "..", "..", "fixtures", "keys"]
      |> Kernel.++(path_segments)
      |> Path.join()
      |> Path.expand()
      |> File.read!()
end
