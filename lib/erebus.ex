defmodule Erebus do
  @cipher :aes_256_gcm

  @moduledoc """
  This is main entry point for Erebus library.
  """

  def encrypt(struct, handle, version, opts) when is_integer(version),
    do: encrypt(struct, handle, Integer.to_string(version), opts)

  def encrypt(struct, handle, version, opts) do
    if struct.changes
       |> Map.keys()
       |> MapSet.new()
       |> MapSet.intersection(MapSet.new(Erebus.Encryption.encrypted_fields(struct.data)))
       |> Enum.empty?() do
      %{}
    else
      struct =
        if is_nil(struct.data.dek) do
          struct
        else
          Map.put(
            struct,
            :data,
            decrypt(struct.data, Erebus.Encryption.encrypted_fields(struct.data))
          )
        end

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
        end)
        |> Enum.filter(& &1)
        |> List.flatten()
        |> Enum.into(%{})

      Map.merge(encrypted_data, %{
        dek: encrypted_dek
      })
    end
  end

  def decrypt(struct, fields_to_decrypt, opts \\ []) do
    encrypted_dek = struct.dek |> Erebus.EncryptedData.cast_if_needed()

    decrypted_dek = Erebus.SymmetricKeyStore.get_key(encrypted_dek, opts)

    decrypted_fields =
      Enum.map(fields_to_decrypt, fn field ->
        stringified_field = Atom.to_string(field)

        encrypted_field = Map.get(struct, String.to_atom(stringified_field <> "_encrypted"))

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
      end)
      |> Enum.into(%{})

    Map.merge(struct, decrypted_fields)
  end
end
