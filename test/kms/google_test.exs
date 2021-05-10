defmodule Erebus.GoogleTest do
  use ExUnit.Case, async: false

  import Mock

  @rsa_public_key {:RSAPublicKey,
                   27_693_458_449_514_005_222_579_440_529_993_482_038_946_075_475_126_655_403_459_101_233_604_394_388_555_678_223_244_748_993_421_634_951_931_300_701_592_769_551_385_962_049_809_028_125_449_319_213_828_156_739_168_214_627_552_688_542_334_360_858_081_843_226_816_359_579_957_072_638_368_190_673_281_234_544_078_217_741_722_742_698_741_649_295_809_169_546_596_216_802_714_885_351_646_574_695_180_861_543_941_437_174_435_871_314_365_772_980_187_033_270_141_469_132_000_832_828_069_180_839_247_679_111_093_016_731_409_671_500_045_321_985_733_852_823_010_254_402_341_504_868_837_341_207_068_888_009_898_746_896_946_820_792_024_443_556_725_798_964_238_912_904_692_223_915_333_954_752_360_168_238_163_616_076_180_423_433_528_337_493_228_935_239_636_301_761_302_761_299_003_705_743_189_136_352_628_689_805_067_275_140_023_762_421_151,
                   65537}

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
      {Goth, [], [fetch: fn _ -> {:ok, %{token: "token"}} end]}
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
      {Goth, [], [fetch: fn _ -> {:ok, %{token: "token"}} end]}
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

  defp read_fixture(path_segments),
    do:
      [__ENV__.file, "..", "..", "fixtures", "keys"]
      |> Kernel.++(path_segments)
      |> Path.join()
      |> Path.expand()
      |> File.read!()
end
