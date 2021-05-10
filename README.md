# Erebus

**TODO: Add description**

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `erebus` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:erebus, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/erebus](https://hexdocs.pm/erebus).

### Required role for Google service account

- Cloud KMS CryptoKey Encrypter/Decrypter
- Cloud KMS CryptoKey Public Key Viewer

### Usage

To use Erebus you need to wrap it and provide your own configuration to calls.

Put following module in your app:

```elixir
defmodule MyApp.Erebus do
  def encrypt(struct, handle, version) do
    opts = Application.get_env(:my_app, :erebus)

    Erebus.encrypt(struct, handle, version, opts)
  end

  def decrypt() do
    opts = Application.get_env(:my_app, :erebus)
  end
end
```

and for encryptable fields define protocol implementation:

```elixir
defimpl Erebus.Encryption do
  def encrypted_fields(_), do: [:first, :second]
end
```

and for that struct add fields named:

```elixir
first
second
first_encrypted
second_encrypted
first_hash
second_hash
dek
```

in case of Ecto, they need to be defined as follows:

```elixir
embedded_schema "table" do
  field(:first_encrypted, :map)
  field(:first_hash, :string)
  field(:second_encrypted, :map)
  field(:second_hash, :string)
  field(:dek, :map)

  field(:first, :string, virtual: true)
  field(:second, :string, virtual: true)
end
```

and provide following values in config:

```elixir
config :my_app, :erebus, kms_backend: Erebus.KMS.Local, keys_base_path: "some_path", private_key_password: "1234"
```

or, in case of using Google KMS:

```elixir
config :my_app, :erebus,
  kms_backend: Erebus.KMS.Google,
  google_project: "someproject",
  google_region: "someregion",
  google_keyring: "some_keyring"
```

After that, you can start using erebus!

```elixir
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

      encrypted_data =
        changes
        |> MyApp.Erebus.encrypt("handle", 1)

      Ecto.Changeset.change(changes, encrypted_data)
    end

    defimpl Erebus.Encryption do
      def encrypted_fields(_), do: [:first, :second]
    end
  end
```

If you don't need multiple encryption keys, provide at hard-coded in `MyApp.Erebus`.
