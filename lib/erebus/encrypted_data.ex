defmodule Erebus.EncryptedData do
  @fields [:encrypted_dek, :handle, :version]

  defstruct @fields

  def cast_if_needed(%__MODULE__{} = encrypted_data), do: encrypted_data

  def cast_if_needed(%{"encrypted_dek" => encrypted_dek, "handle" => handle, "version" => version}),
      do: %Erebus.EncryptedData{
        encrypted_dek: encrypted_dek,
        handle: handle,
        version: version
      }
end
