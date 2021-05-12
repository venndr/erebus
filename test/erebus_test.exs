defmodule Erebus.Test do
  use ExUnit.Case
  doctest Erebus

  setup do
    Erebus.PublicKeyStore.init()
    Erebus.PrivateKeyStore.init()
    Erebus.SymmetricKeyStore.init()

    :ok
  end

  defmodule EncryptedStuff do
    use Ecto.Schema
    import Ecto.Changeset
    import Erebus.Schema

    embedded_schema do
      hashed_encrypted_field(:first)
      hashed_encrypted_field(:second)
      data_encryption_key()

      field(:other, :string)
    end

    def changeset(stuff, attrs, force_reencrypt \\ false) do
      changes =
        stuff
        |> cast(attrs, [
          :first,
          :second
        ])

      encrypted_data =
        changes
        |> Erebus.encrypt("handle", 1,
          kms_backend: Erebus.TestBackend,
          force_reencrypt: force_reencrypt
        )

      Ecto.Changeset.change(changes, encrypted_data)
    end

    defimpl Erebus.Encryption do
      def encrypted_fields(_), do: [:first, :second]
    end
  end

  test "encrypting and decrypting data with ecto" do
    model = %EncryptedStuff{}

    encrypted =
      model
      |> EncryptedStuff.changeset(%{first: "hello", second: "there"})
      |> Ecto.Changeset.apply_changes()
      # simulate reloading with virtual fields emptied
      |> Map.merge(%{first: nil, second: nil})

    assert !is_nil(encrypted.dek)
    assert !is_nil(encrypted.first_hash)
    assert !is_nil(encrypted.first_encrypted)

    assert encrypted.first_hash == :crypto.hash(:sha512, "hello") |> Base.encode64()

    decrypted_first =
      encrypted
      |> Erebus.decrypt([:first],
        kms_backend: Erebus.TestBackend
      )

    assert "hello" == decrypted_first.first
    assert nil == decrypted_first.second

    decrypted_second =
      decrypted_first
      |> Erebus.decrypt([:second],
        kms_backend: Erebus.TestBackend
      )

    assert "hello" == decrypted_second.first
    assert "there" == decrypted_second.second

    # reencryption
    hash_before = encrypted.first_encrypted
    dek_before = encrypted.dek

    encrypted_2 =
      encrypted
      |> EncryptedStuff.changeset(%{second: "thereX"})
      |> Ecto.Changeset.apply_changes()

    assert hash_before != encrypted_2.first_encrypted
    assert dek_before != encrypted_2.dek

    # when changing other fields it shouldnt reencrypt

    encrypted_3 =
      encrypted
      |> EncryptedStuff.changeset(%{other: "somestring"})
      |> Ecto.Changeset.apply_changes()

    assert hash_before == encrypted_3.first_encrypted
    assert dek_before == encrypted_3.dek
  end

  test "encrypting and decrypting data with one field being null" do
    model = %EncryptedStuff{}

    encrypted =
      model
      |> EncryptedStuff.changeset(%{first: "hello"})
      |> Ecto.Changeset.apply_changes()
      # simulate reloading with virtual fields emptied
      |> Map.merge(%{first: nil})

    assert !is_nil(encrypted.dek)
    assert !is_nil(encrypted.first_hash)
    assert !is_nil(encrypted.first_encrypted)
    assert is_nil(encrypted.second_hash)
    assert is_nil(encrypted.second_encrypted)

    decrypted_first =
      encrypted
      |> Erebus.decrypt([:first, :second],
        kms_backend: Erebus.TestBackend
      )

    assert "hello" == decrypted_first.first
    assert nil == decrypted_first.second
  end

  test "forcing data reencryption" do
    model = %EncryptedStuff{first: "hello"}

    encrypted =
      model
      |> EncryptedStuff.changeset(%{}, true)
      |> Ecto.Changeset.apply_changes()
      # simulate reloading with virtual fields emptied
      |> Map.merge(%{first: nil})

    assert !is_nil(encrypted.dek)
    assert !is_nil(encrypted.first_hash)
    assert !is_nil(encrypted.first_encrypted)
    assert is_nil(encrypted.second_hash)
    assert is_nil(encrypted.second_encrypted)

    decrypted_first =
      encrypted
      |> Erebus.decrypt([:first],
        kms_backend: Erebus.TestBackend
      )

    assert "hello" == decrypted_first.first
  end

  test "reencrypting dek" do
    model = %EncryptedStuff{}

    encrypted =
      model
      |> EncryptedStuff.changeset(%{first: "hello", second: "there"})
      |> Ecto.Changeset.apply_changes()
      # simulate reloading with virtual fields emptied
      |> Map.merge(%{first: nil, second: nil})

    assert !is_nil(encrypted.dek)
    assert !is_nil(encrypted.first_hash)
    assert !is_nil(encrypted.first_encrypted)

    %{dek: reencrypted_dek} =
      Erebus.reencrypt_dek(encrypted, "handle", 1, kms_backend: Erebus.TestBackend)

    assert reencrypted_dek.encrypted_dek != encrypted.dek.encrypted_dek
  end
end
