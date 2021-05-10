defmodule Erebus.SymmetricKeyStore do
  @table :erebus_symmetric_key_store

  def init() do
    @table |> :ets.whereis() |> create_table_if_needed()
  end

  defp create_table_if_needed(:undefined),
    do: :ets.new(@table, [:set, :public, :named_table])

  defp create_table_if_needed(_), do: nil

  def get_key(encrypted, opts) do
    key = :ets.lookup(@table, encrypted)

    return_or_fetch(key, encrypted, opts)
  end

  defp return_or_fetch([], encrypted, opts) do
    symmetric_key = Erebus.KMS.decrypt(encrypted, opts)

    :ets.insert(@table, {encrypted, symmetric_key})

    symmetric_key
  end

  defp return_or_fetch([{_, key} | _], _handle, _version), do: key
end
