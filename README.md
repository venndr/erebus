# Erebus

[![Elixir CI](https://github.com/venndr/erebus/actions/workflows/elixir.yml/badge.svg)](https://github.com/venndr/erebus/actions/workflows/elixir.yml)

Erebus is an implementation of the envelope encryption paradigm. For each encrypted struct, it's using a separate key - called DEK
(short for data encryption key). It's regenerated (hence re-encrypting fields) on each save - making key encryption barely needed.
During each encryption, DEK is encrypted using KEK (key encryption key). DEK is a symmetric key - we're using
Aes 256 with Galois mode with aead (which guarantees both security and integrity of the data). KEK is an asymmetric key - we're
using a public key for encryption (for performance reason when using external key storage) and private for decryption. Specific implementation
depends on the backend. Currently, we're providing three:

- `Erebus.KMS.Google` - which uses Google KMS key storage. That means that your private key never leaves Google infrastructure,
  which is the most secure option.
- `Erebus.KMS.Local` - which uses private/public key pair stored on your hard drive. Please note that it makes them prone to leakage
- `Erebus.KMS.Dummy` - which uses base64 as encryption for DEK. Never use it in production.

Please note that you need to provide config for the operations and call them, providing them for each call.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `erebus` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:erebus, "~> 0.2.0"}
  ]
end
```

## Usage

To use Erebus, you need to wrap it and provide your configuration to calls.

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

in the case of Ecto, they need to be defined as follows:

```elixir
use Erebus.Schema

embedded_schema "table" do
  hashed_encrypted_field(:first)
  hashed_encrypted_field(:second)
  data_encryption_key()
end
```

### Usage with local KMS adapter

Provide following values in config:

```elixir
config :my_app, :erebus, kms_backend: Erebus.KMS.Local, keys_base_path: "some_path", private_key_password: "1234"
```

And generate asymmetric key pairs in that folder.

### Usage with Google KMS adapter

Please add to your application Goth:

```
{:goth, "~> 1.3.0-rc.2"}
```

and start it in your application.ex:

```elixir
credentials =
  "GCP_KMS_CREDENTIALS_PATH"
  |> System.fetch_env!()
  |> File.read!()
  |> Jason.decode!()

scopes = ["https://www.googleapis.com/auth/cloudkms"]

source = {:service_account, credentials, scopes: scopes}

children = [
  {Goth, name: MyApp.Goth, source: source}
]
```

and provide name as one of the options to Erebus:

```elixir
config :my_app, :erebus,
  kms_backend: Erebus.KMS.Google,
  google_project: "someproject",
  google_region: "someregion",
  google_keyring: "some_keyring",
  google_goth: MyApp.Goth
```

Please note that if you're using Google KMS, your key must have access to the following roles:

- Cloud KMS CryptoKey Encrypter/Decrypter
- Cloud KMS CryptoKey Public Key Viewer

### Ecto usage full example

```elixir
defmodule EncryptedStuff do
    use Ecto.Schema
    import Ecto.Changeset
    use Erebus.Schema

    embedded_schema do
      hashed_encrypted_field(:first)
      hashed_encrypted_field(:second)
      data_encryption_key()
      field(:other, :string)
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

Currently, we support only encoding / decoding data using Ecto changeset.
