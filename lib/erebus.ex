defmodule Erebus do
  @cipher :aes_256_gcm

  @moduledoc """
  This is entrypoint for Erebus library. Here you will find operations for both encrypting and decrypting fields in the database.

  Erebus is an implementation of envelope encryption paradigm. For each encrypted struct it's using separate key - called DEK
  (short for data encryption key). Then that key is encrypted using KEK (key encryption key). DEK is a symmetric key - we're using
  Aes 256 with galois mode with aead (which guarantees both security and integrity of the data). KEK is an asymmetric key - we're
  using public key for encryption (for performance reason when using external key storage) and private for decryption. Specific implementation
  depends on the backend. Currently we're providing three:
  * `Erebus.KMS.Google` - which uses Google KMS key storage. That basically means that your private key never leaves Google infrastructure,
  which is most secure option.
  * `Erebus.KMS.Local` - which uses private/public key pair stored on your hard drive. Please note that it makes them prone to leakage
  * `Erebus.KMS.Dummy` - which uses base64 as encryption for DEK. Never use it in production.

  Please note that you need to provide config for the operations and call them providing them for each call.

  Preferred way of running it is with your own wrapper, like:

  ```
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

  while providing config in your app config file, so for Google KMS it would be:
  ```
  config :my_app, :erebus,
    kms_backend: Erebus.KMS.Google,
    google_project: "someproject",
    google_region: "someregion",
    google_keyring: "some_keyring",
    google_goth: MyApp.Goth
  ```

  and for using local key file, it would be:
  ```
  config :my_app, :erebus,
    kms_backend: Erebus.KMS.Local,
    keys_base_path: "/tmp/keys",
    private_key_password: "1234"
  ```

  Please note that by using that approach you can use different Erebus config for
  less vital data (using local keys) and more vital (using more secure Google KMS).
  """

  @doc false
  def encrypt(struct, handle, version, opts) when is_integer(version),
    do: encrypt(struct, handle, Integer.to_string(version), opts)

  @doc """
  This function should be called when you want to encrypt your struct. It takes:
  * struct which implements `Erebus.Encryption` protocol
  * handle for key
  * version of key
  * options - providing backend and options for that backend

  One very meaningful option is `:force_reencrypt` flag,
  which can be used to for reencrypting all of the fields - even if nothing has been changed there.
  """
  def encrypt(struct, handle, version, opts),
    do:
      do_encrypt(
        struct,
        handle,
        version,
        opts,
        changing_encrypted_fields?(struct) || Keyword.get(opts, :force_reencrypt, false)
      )

  @doc """
  This function decrypts your encrypted struct. It takes:
  * encrypted struct with `dek` field present
  * list of fields to be decrypted
  * options - providing backend and options for that backend
  """
  def decrypt(struct, fields_to_decrypt, opts \\ []) do
    encrypted_dek = struct.dek |> Erebus.EncryptedData.cast_if_needed()

    decrypted_dek = Erebus.SymmetricKeyStore.get_key(encrypted_dek, opts)

    decrypted_fields =
      Enum.map(fields_to_decrypt, fn field ->
        stringified_field = Atom.to_string(field)

        encrypted_field = Map.get(struct, String.to_atom(stringified_field <> "_encrypted"))

        case encrypted_field do
          nil ->
            nil

          _ ->
            <<iv::binary-16, aead::binary-16, ciphertag::binary-16, ciphertext::binary>> =
              Base.decode64!(encrypted_field)

            {field,
             :crypto.crypto_one_time_aead(
               @cipher,
               decrypted_dek,
               iv,
               ciphertext,
               aead,
               ciphertag,
               false
             )}
        end
      end)
      |> Enum.filter(& &1)
      |> Enum.into(%{})

    Map.merge(struct, decrypted_fields)
  end

  @doc false
  def reencrypt_dek(struct, handle, version, opts) when is_integer(version),
    do: reencrypt_dek(struct, handle, Integer.to_string(version), opts)

  @doc """
  This method called on encrypted struct, force it to reencrypt DEK using provided KEK backend.
  """
  def reencrypt_dek(%{dek: dek}, handle, version, opts) do
    decrypted_dek = Erebus.KMS.decrypt(dek, opts)

    newly_encrypted_dek =
      Erebus.KMS.encrypt(decrypted_dek |> Base.encode64(), handle, version, opts)

    %{dek: newly_encrypted_dek}
  end

  defp changing_encrypted_fields?(%{changes: changes, data: data}),
    do:
      changes
      |> Map.keys()
      |> MapSet.new()
      |> MapSet.intersection(MapSet.new(Erebus.Encryption.encrypted_fields(data)))
      |> Enum.empty?()
      |> Kernel.not()

  defp changing_encrypted_fields?(_), do: false

  defp force_decrypt(%{data: %{dek: dek} = data} = struct) when not is_nil(dek),
    do: %{struct | data: decrypt(data, Erebus.Encryption.encrypted_fields(data))}

  defp force_decrypt(struct), do: struct

  defp do_encrypt(_struct, _handle, _version, _opts, false), do: %{}

  defp do_encrypt(struct, handle, version, opts, true) do
    struct = force_decrypt(struct)

    dek = :crypto.strong_rand_bytes(32) |> Base.encode64()

    encrypted_dek = Erebus.KMS.encrypt(dek, handle, version, opts)

    encrypted_data =
      struct.data
      |> Erebus.Encryption.encrypted_fields()
      |> Enum.map(fn
        nil ->
          nil

        field ->
          aead = :crypto.strong_rand_bytes(16)
          iv = :crypto.strong_rand_bytes(16)

          stringified = Atom.to_string(field)

          data_to_encrypt = struct.changes |> Map.get(field) || Map.get(struct.data, field)

          if not is_nil(data_to_encrypt) do
            {ciphertext, ciphertag} =
              :crypto.crypto_one_time_aead(
                @cipher,
                dek |> Base.decode64!(),
                iv,
                data_to_encrypt,
                aead,
                16,
                true
              )

            [
              {
                String.to_atom(stringified <> "_encrypted"),
                Base.encode64(
                  iv <>
                    aead <>
                    ciphertag <>
                    ciphertext
                )
              },
              {
                String.to_atom(stringified <> "_hash"),
                :crypto.hash(:sha512, data_to_encrypt) |> Base.encode64()
              }
            ]
          end
      end)
      |> Enum.filter(& &1)
      |> List.flatten()
      |> Enum.into(%{})

    Map.merge(encrypted_data, %{
      dek: encrypted_dek
    })
  end
end
