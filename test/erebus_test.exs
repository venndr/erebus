defmodule ErebusTest do
  use ExUnit.Case
  doctest Erebus

  defmodule EncryptedStuff do
    # use Erebus.Encryption, fields: [:first, :second]

    use Ecto.Schema
    import Ecto.Changeset

    embedded_schema do
      field(:first_encrypted, :map)
      field(:first_hash, :string)
      field(:second_encrypted, :map)
      field(:second_hash, :string)
      field(:dek, :map)

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
      |> IO.inspect(label: "applied")
      |> IO.inspect(label: "Encrypted model")

    decrypted_first =
      encrypted |> Erebus.decrypt([:first]) |> IO.inspect(label: "first decrypted")

    decrypted_second =
      decrypted_first |> Erebus.decrypt([:second]) |> IO.inspect(label: "second decrypted")
  end
end
