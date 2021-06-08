defmodule Erebus.EncryptedData do
  @moduledoc """
  This module stores data needed for decrypting encrypted struct. It stores:
  * encrypted dek
  * handle of the key used to encrypt it
  * version of the key used to encrypt it
  """

  @fields [:encrypted_dek, :handle, :version]

  @type t :: %Erebus.EncryptedData{
          encrypted_dek: any(),
          handle: binary(),
          version: binary()
        }

  @derive Jason.Encoder
  defstruct @fields

  @doc false
  def cast_if_needed(%__MODULE__{} = encrypted_data), do: encrypted_data

  @doc false
  def cast_if_needed(%{"encrypted_dek" => encrypted_dek, "handle" => handle, "version" => version}),
      do: %Erebus.EncryptedData{
        encrypted_dek: encrypted_dek,
        handle: handle,
        version: version
      }
end
