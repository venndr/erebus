defmodule Erebus.Schema do
  defmacro hashed_encrypted_field(name) do
    quote do
      field unquote(name), :string, virtual: true
      field String.to_atom("#{unquote(name)}_encrypted"), :map
      field String.to_atom("#{unquote(name)}_hash"), :string
    end
  end

  defmacro encrypted_field(name) do
    quote do
      field unquote(name), :string, virtual: true
      field String.to_atom("#{unquote(name)}_encrypted"), :map
    end
  end

  defmacro data_encryption_key() do
    quote do
      field :dek, :map
    end
  end
end
