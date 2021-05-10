defmodule Erebus.KMS.Local do
  @behaviour Erebus.KMS

  @impl true
  def decrypt(
        %Erebus.EncryptedData{
          encrypted_dek: encrypted_dek,
          handle: handle,
          version: version
        },
        opts
      ) do
    private_key = Erebus.PrivateKeyStore.get_key(handle, version, opts)

    :public_key.decrypt_private(
      encrypted_dek |> Base.decode64!(),
      private_key,
      rsa_padding: :rsa_pkcs1_oaep_padding,
      rsa_mgf1_md: :sha256,
      rsa_oaep_md: :sha256
    )
  end

  @impl true
  def encrypt(dek, handle, version, opts) do
    public_key = Erebus.PublicKeyStore.get_key(handle, version, opts)

    %Erebus.EncryptedData{
      encrypted_dek:
        :public_key.encrypt_public(
          dek,
          public_key,
          rsa_padding: :rsa_pkcs1_oaep_padding,
          rsa_mgf1_md: :sha256,
          rsa_oaep_md: :sha256
        )
        |> Base.encode64(),
      handle: handle,
      version: version
    }
  end

  def get_public_key(handle, version, opts) do
    base_path = Keyword.fetch!(opts, :keys_base_path)

    base_path
    |> Path.join(handle)
    |> Path.join(version)
    |> Path.join("public.pem")
    |> File.read!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  def get_private_key(handle, version, opts) do
    base_path = Keyword.fetch!(opts, :keys_base_path)
    password = Keyword.fetch!(opts, :private_key_password) |> to_charlist()

    base_path
    |> Path.join(handle)
    |> Path.join(version)
    |> Path.join("private.pem")
    |> File.read!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode(password)
  end
end
