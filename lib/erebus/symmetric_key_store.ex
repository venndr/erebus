defmodule Erebus.SymmetricKeyStore do
  @table :erebus_symmetric_key_store

  @moduledoc """
  This module serves as cache storage using ETS for decrypted DEKs.
  """

  @doc false
  def init() do
    @table |> :ets.whereis() |> create_table_if_needed()
  end

  @doc """
  Get DEK from the ETS cache OR decrypt it using provided KMS backend.
  """
  def get_key(encrypted, opts) do
    suffix = Keyword.get(opts, :suffix, "")
    key = :ets.lookup(@table, calculate_key(encrypted, suffix))

    return_or_fetch(key, encrypted, opts)
  end

  defp create_table_if_needed(:undefined),
    do:
      :ets.new(@table, [
        :set,
        :public,
        :named_table
      ])

  defp create_table_if_needed(_), do: nil

  defp return_or_fetch([], encrypted, opts) do
    suffix = Keyword.get(opts, :suffix, "")
    symmetric_key = Erebus.KMS.decrypt(encrypted, opts)

    calculated_key = calculate_key(encrypted, suffix)

    :ets.insert(@table, {calculated_key, symmetric_key})

    Task.start(fn -> expire_cache_entry(calculated_key) end)

    symmetric_key
  end

  defp return_or_fetch([{_, key} | _], _handle, _version), do: key

  @doc false
  def expire_cache_entry(key) do
    15 |> :timer.minutes() |> :timer.sleep()
    :ets.delete(@table, key)
  end

  defp calculate_key(encrypted, suffix), do: {encrypted, suffix}
end
