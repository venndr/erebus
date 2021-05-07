defmodule ErebusTest do
  use ExUnit.Case
  doctest Erebus

  defmodule EncryptedStuff do
    use Ecto.Schema
    import Ecto.Changeset

    embedded_schema do
      field(:first_encrypted, :map)
      field(:first_hash, :string)
      field(:second_encrypted, :map)
      field(:second_hash, :string)
      field(:dek, :map)
      field(:other, :string)

      field(:first, :string, virtual: true)
      field(:second, :string, virtual: true)
    end

    def changeset(stuff, attrs) do
      changes =
        stuff
        |> cast(attrs, [
          :first,
          :second
        ])

      encrypted_data = changes |> Erebus.encrypt("staging-master", 3)

      Ecto.Changeset.change(changes, encrypted_data)
    end

    defimpl Erebus.Encryption do
      def encrypted_fields(_), do: [:first, :second]
    end
  end

  test "encrypting and decrypting data" do
    model = %EncryptedStuff{}

    encrypted =
      model
      |> EncryptedStuff.changeset(%{first: "hello", second: "there"})
      |> Ecto.Changeset.apply_changes()
      # simulate reloading with virtual fields emptied
      |> Map.merge(%{first: nil, second: nil})

    decrypted_first = encrypted |> Erebus.decrypt([:first])

    assert "hello" == decrypted_first.first
    assert nil == decrypted_first.second

    decrypted_second = decrypted_first |> Erebus.decrypt([:second])

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
end
