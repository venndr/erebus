defmodule Erebus.PrivateKeyStore do
  @table :erebus_private_key_store

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

  def get_key(handle, version, opts) do
    key = :ets.lookup(@table, calculate_key(handle, version))

    return_or_fetch(key, handle, version, opts)
  end

  defp return_or_fetch([], handle, version, opts) do
    private_key = Erebus.KMS.get_private_key(handle, version, opts)
    calculated_key = calculate_key(handle, version)

    :ets.insert(@table, {calculated_key, private_key})

    Task.start(fn -> expire_cache_entry(calculated_key) end)

    private_key
  end

  defp return_or_fetch([{_, key} | _], _handle, _version, _opts), do: key

  defp calculate_key(handle, version), do: handle <> "#" <> version

  def expire_cache_entry(key) do
    15 |> :timer.minutes() |> :timer.sleep()
    :ets.delete(@table, key)
  end
end
