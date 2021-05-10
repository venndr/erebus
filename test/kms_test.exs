defmodule Erebus.KMSTest do
  use ExUnit.Case

  test "must forward decrypt to backend" do
    defmodule DecryptBackend do
      def decrypt(_, _), do: Base.encode64("decrypted")
    end

    assert "decrypted" == Erebus.KMS.decrypt(%Erebus.EncryptedData{}, kms_backend: DecryptBackend)
  end

  test "must forward encrypt to backend" do
    defmodule EncryptBackend do
      def encrypt(_, _, _, _), do: "encrypted"
    end

    assert "encrypted" ==
             Erebus.KMS.encrypt("dek", "handle", "version", kms_backend: EncryptBackend)
  end

  test "must forward get_public_key to backend" do
    defmodule PublicKeyBackend do
      def get_public_key(_, _, _), do: "public_key"
    end

    assert "public_key" ==
             Erebus.KMS.get_public_key("handle", "version", kms_backend: PublicKeyBackend)
  end

  test "must forward get_private_key to backend" do
    defmodule PrivateKeyBackend do
      def get_private_key(_, _, _), do: "private_key"
    end

    assert "private_key" ==
             Erebus.KMS.get_private_key("handle", "version", kms_backend: PrivateKeyBackend)
  end

  test "must throw exception when get_public_key is missing in backend" do
    defmodule DummyBackend1 do
    end

    assert_raise RuntimeError,
                 "Provided backend Elixir.Erebus.KMSTest.DummyBackend1 does not support fetching public key!",
                 fn ->
                   Erebus.KMS.get_public_key("handle", "version", kms_backend: DummyBackend1)
                 end
  end

  test "must throw exception when get_private_key is missing in backend" do
    defmodule DummyBackend2 do
    end

    assert_raise RuntimeError,
                 "Provided backend Elixir.Erebus.KMSTest.DummyBackend2 does not support fetching private key!",
                 fn ->
                   Erebus.KMS.get_private_key("handle", "version", kms_backend: DummyBackend2)
                 end
  end
end
