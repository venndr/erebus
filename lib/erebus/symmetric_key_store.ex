defmodule Erebus.SymmetricKeyStore do
  @table :erebus_symmetric_key_store

  def init() do
    @table |> :ets.whereis() |> create_table_if_needed()
  end

  defp create_table_if_needed(:undefined),
    do:
      :ets.new(@table, [
        :set,
        :public,
        :named_table
      ])

  defp create_table_if_needed(_), do: nil

  def get_key(encrypted, opts) do
    key = :ets.lookup(@table, encrypted)

    return_or_fetch(key, encrypted, opts)
  end

  defp return_or_fetch([], encrypted, opts) do
    symmetric_key = Erebus.KMS.decrypt(encrypted, opts)

    :ets.insert(@table, {encrypted, symmetric_key})

    Task.start(fn -> expire_cache_entry(encrypted) end)

    symmetric_key
  end

  defp return_or_fetch([{_, key} | _], _handle, _version), do: key

  def expire_cache_entry(key) do
    15 |> :timer.minutes() |> :timer.sleep()
    :ets.delete(@table, key)
  end
end
