defmodule Erebus.Schema do
  @moduledoc """
  This module provides convenient macros to define fields in your Ecto model easily.

  Usage:
  ```elixir
  use Erebus.Schema
  use Ecto.Schema

  embedded_schema do
      hashed_encrypted_field(:first)
      data_encryption_key()
    end
  """

  @doc """
  Defines three fields:
  - `name`: virtual field of type `string`
  - `name_encrypted`: field of type `binary` storing encrypted data
  - `name_hash`: field of type `string`, storing sha512 version of given data, for quick searching

  Please note that if you're using it with a database underneath, these fields need to be of type:
  - `name_encrypted`: `bytea`
  - `name_hash`: `text`
  """
  defmacro hashed_encrypted_field(name) do
    quote do
      field(unquote(name), :string, virtual: true)
      field(String.to_atom("#{unquote(name)}_encrypted"), :binary)
      field(String.to_atom("#{unquote(name)}_hash"), :string)
    end
  end

  @doc """
  Defines field dek of type `map`, which is required for storing encrypted information using Erebus.

  Please note that if you're using it with a database underneath, this field needs to be of type `jsonb` underneath.
  """
  defmacro data_encryption_key() do
    quote do
      field(:dek, :map)
    end
  end
end
