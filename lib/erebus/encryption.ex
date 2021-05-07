defmodule Erebus.Encryption do
  defmacro __using__(encrypted_fields) do
    quote do
      import Erebus.Encryption

      Module.register_attribute(__MODULE__, :encrypted_fields, accumulate: true, persist: true)

      Module.put_attribute(
        __MODULE__,
        :encrypted_fields,
        "X"
      )

      # def match(m, [], _ctx), do: m
    end
  end
end
