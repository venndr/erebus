defmodule Erebus.PrivateKeyStore do
  @table :erebus_private_key_store

  def init() do
    @table |> :ets.whereis() |> create_table_if_needed()
  end

  defp create_table_if_needed(:undefined),
    do: :ets.new(@table, [:set, :public, :named_table])

  defp create_table_if_needed(_), do: nil

  def get_key(handle, version, opts) do
    key = :ets.lookup(@table, calculate_key(handle, version))

    return_or_fetch(key, handle, version, opts)
  end

  defp return_or_fetch([], handle, version, opts) do
    public_key = Erebus.KMS.get_private_key(handle, version, opts)

    :ets.insert(@table, {calculate_key(handle, version), public_key})

    public_key
  end

  defp return_or_fetch([key | _], _handle, _version, _opts), do: key

  defp calculate_key(handle, version), do: handle <> "#" <> version
end
