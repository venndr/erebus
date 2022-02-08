# Erebus

[![Elixir CI](https://github.com/venndr/erebus/actions/workflows/elixir.yml/badge.svg)](https://github.com/venndr/erebus/actions/workflows/elixir.yml)

Erebus is an implementation of the envelope encryption paradigm. It uses a separate key (called DEK, short for data encryption key) for each encrypted struct. The key is regenerated on each save, making key encryption barely necessary.  During each encryption, the DEK is encrypted using the KEK (key encryption key).

The DEK is a symmetric key (Erebus uses AES-256 with Galois mode (AES-GCM) with AEAD), which guarantees both the security and the integrity of the data. The KEK is an asymmetric key – Erebus uses the public key for encryption (for performance reasons when using external key storage) and the private key for decryption. The specific implementation depends on the backend.

Currently, there are three supported backend implementations:

- `Erebus.KMS.Google` - Google KMS key storage. Means that your private key never leaves Google infrastructure,
  which is the most secure option
- `Erebus.KMS.Local` - private/public key pair stored on your hard drive. Please note that it makes them prone to leakage
- `Erebus.KMS.Dummy` - base64 as encryption for DEK. Never use it in production

Please note that you need to provide config for the operations and explicitly invoke them, providing the config on every call.

## Installation

Erebus can be installed by adding `erebus` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:erebus, "~> 0.2.0-rc.3"}
  ]
end
```

## Usage

To use Erebus you need to wrap it to provide your backend configuration. Create a module like the example below in your app:

```elixir
defmodule MyApp.Erebus do
  def encrypt(struct, handle, version) do
    opts = Application.get_env(:my_app, :erebus)

    Erebus.encrypt(struct, handle, version, opts)
  end

  def decrypt(struct, fields) do
    opts = Application.get_env(:my_app, :erebus)

    Erebus.decrypt(struct, fields, opts)
  end
end
```

In an encrypted struct, Erebus requires several fields for each encrypted property. Follow the
example below to define your structs:

```elixir
defmodule SecureModel
  @type t :: %__MODULE__{
      # `first` is an encrypted field
      first: String.t(),
      # `second` is another encrypted field
      second: String.t(),

      # this field contains the ciphertext for the `first` field
      first_encrypted: binary(),
      # this field contains the ciphertext for the `second` field
      second_encrypted: binary(),

      # this field contains a hashed version of the unencrypted `first` field
      first_hash: String.t(),
      # this field contains a hashed version of the unencrypted `second` field
      second_hash: String.t(),

      # this field contains the DEK (data encryption key)
      dek: map()
    }
end
```

In this example `first` and `second` are the names of the encryptable fields. The _unsuffixed_ fields are virtual, meaning they are only used for encrypting (before write), or are populated after decrypting the equivalent `*_encrypted` fields – only _suffixed_ fields are written to the database. The `dek` field contains the DEK.

The `*_hash` suffixed fields are hashed (using SHA512) versions of the plain text field content. They can be used for finding exact matches without having to decrypt the content.

When using [Ecto](https://hex.pm/packages/ecto), fields are defined using the `hashed_encrypted_field(:field_name)` and `data_encryption_key()` macros, which create all the necessary auxiliary fields for you:

```elixir
use Erebus.Schema

embedded_schema "table" do
  hashed_encrypted_field(:first)
  hashed_encrypted_field(:second)
  data_encryption_key()
end
```

Additionally you must implement the `Erebus.Encryption` protocol to mark the fields which should be encrypted:

```elixir
defimpl Erebus.Encryption do
  def encrypted_fields(_), do: [:first, :second]
end
```

### Usage with local KMS adapter

1. Set the following values in your application config:
    ```elixir
    config :my_app, :erebus,
      kms_backend: Erebus.KMS.Local,
      keys_base_path: "path_to_directory_containing_a_key_pair",
      private_key_password: "1234"
    ```
2. Generate asymmetric key pairs (named `public.pem` and `private.pem`) in the folder at `keys_base_path`.

### Usage with Google KMS adapter

1. Include [Goth](https://hex.pm/packages/goth) in your application:
    ```elixir
    {:goth, "~> 1.3.0-rc.2"}
    ```
2. Start Goth in your `application.ex`:
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
3. Pass the app's `name` in the `google_goth` option to Erebus:
    ```elixir
    config :my_app, :erebus,
      kms_backend: Erebus.KMS.Google,
      google_project: "someproject",
      google_region: "someregion",
      google_keyring: "some_keyring",
      google_goth: MyApp.Goth
    ```

Please note that if you're using Google KMS, your key must have access to the following roles:

- [Cloud KMS CryptoKey Encrypter](https://cloud.google.com/kms/docs/reference/permissions-and-roles#cloudkms.cryptoKeyEncrypter)
- [Cloud KMS CryptoKey Decrypter](https://cloud.google.com/kms/docs/reference/permissions-and-roles#cloudkms.cryptoKeyDecrypter)
- [Cloud KMS CryptoKey Public Key Viewer](https://cloud.google.com/kms/docs/reference/permissions-and-roles#cloudkms.publicKeyViewer)

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

Currently Erebus only supports encoding and decoding data using Ecto changeset.
