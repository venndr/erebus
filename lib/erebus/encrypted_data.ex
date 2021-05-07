defmodule Erebus.EncryptedData do
  @fields [:encrypted_dek, :ciphertext, :handle, :version]

  defstruct @fields
end
