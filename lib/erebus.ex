defmodule Erebus do
  @cipher :aes_256_gcm

  @moduledoc """
  Documentation for `Erebus`.
  """

  def encrypt(struct, handle, version) when is_integer(version),
    do: encrypt(struct, handle, Integer.to_string(version))

  def encrypt(struct, handle, version) do
    dek = :crypto.strong_rand_bytes(32) |> Base.encode64()

    encrypted_dek = Erebus.KMS.encrypt(dek, handle, version)

    aead = :crypto.strong_rand_bytes(16)
    iv = :crypto.strong_rand_bytes(16)

    {ciphertext, ciphertag} =
      :crypto.crypto_one_time_aead(@cipher, dek |> Base.decode64!(), iv, struct, aead, 16, true)

    dek = nil
    :erlang.garbage_collect(self())
    # force removing of unencrypted dek from memory

    Map.put(
      encrypted_dek,
      :ciphertext,
      Base.encode64(
        iv <>
          aead <>
          ciphertag <>
          ciphertext
      )
    )
  end

  def decrypt(
        %Erebus.EncryptedData{
          ciphertext: ciphertext_base64
        } = encrypted_data
      ) do
    decrypted_dek = Erebus.KMS.decrypt(encrypted_data)

    <<iv::binary-16, aead::binary-16, ciphertag::binary-16, ciphertext::binary>> =
      Base.decode64!(ciphertext_base64)

    decrypted_data =
      :crypto.crypto_one_time_aead(
        @cipher,
        decrypted_dek |> Base.decode64!(),
        iv,
        ciphertext,
        aead,
        ciphertag,
        false
      )

    decrypted_dek = nil
    :erlang.garbage_collect(self())
    # force removing of unencrypted dek from memory

    decrypted_data
  end
end
