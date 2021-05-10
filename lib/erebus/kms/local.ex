# defmodule Erebus.KMS.Local do
#   @behaviour Erebus.KMS

#   # @impl true
#   # def decrypt(%Erebus.EncryptedData{
#   #       encrypted_dek: encrypted_dek,
#   #       handle: handle,
#   #       version: version
#   #     }) do
#   # end

#   # @impl true
#   # def encrypt(dek, handle, version) do
#   #   public_key = Erebus.PublicKeyStore.get_key(handle, version)

#   #   %Erebus.EncryptedData{
#   #     encrypted_dek:
#   #       :public_key.encrypt_public(dek, public_key,
#   #         rsa_padding: :rsa_pkcs1_oaep_padding,
#   #         rsa_mgf1_md: :sha256,
#   #         rsa_oaep_md: :sha256
#   #       )
#   #       |> Base.encode64(),
#   #     handle: handle,
#   #     version: version
#   #   }
#   # end

#   # @impl true
#   # def get_public_key(handle, version) do
#   #   public_key
#   #   |> :public_key.pem_decode()
#   #   |> hd()
#   #   |> :public_key.pem_entry_decode()
#   # end
# end
