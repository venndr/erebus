defmodule Erebus.PrivateKeyStore do
  @table :erebus_private_key_store

  @moduledoc """
  This module serves as cache storage using ETS for private keys.
  """

  def init() do
    @table |> :ets.whereis() |> create_table_if_needed()
  end

  @doc """
  Get the private key from the ETS cache OR fetch it from the backend - if the backend supports it.
  """
  def get_key(handle, version, opts) do
    suffix = Keyword.get(opts, :suffix, "")
    key = :ets.lookup(@table, calculate_key(handle, version, suffix))

    return_or_fetch(key, handle, version, opts)
  end

  @doc false
  def expire_cache_entry(key) do
    15 |> :timer.minutes() |> :timer.sleep()
    :ets.delete(@table, key)
  end

  defp create_table_if_needed(:undefined),
    do:
      :ets.new(@table, [
        :set,
        :public,
        :named_table
      ])

  defp create_table_if_needed(_), do: nil

  defp return_or_fetch([], handle, version, opts) do
    suffix = Keyword.get(opts, :suffix, "")
    private_key = Erebus.KMS.get_private_key(handle, version, opts)
    calculated_key = calculate_key(handle, version, suffix)

    :ets.insert(@table, {calculated_key, private_key})

    Task.start(fn -> expire_cache_entry(calculated_key) end)

    private_key
  end

  defp return_or_fetch([{_, key} | _], _handle, _version, _opts), do: key

  defp calculate_key(handle, version, suffix), do: {handle, version, suffix}
end
