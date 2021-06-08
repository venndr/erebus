defmodule Erebus.PublicKeyStore do
  @table :erebus_public_key_store

  @moduledoc """
  This module serves as cache storage using ETS for public keys.
  """

  def init() do
    @table |> :ets.whereis() |> create_table_if_needed()
  end

  @doc """
  Get public key from ETS cache OR fetch it from backend.
  """
  def get_key(handle, version, opts) do
    suffix = Keyword.get(opts, :suffix, "")
    key = :ets.lookup(@table, calculate_key(handle, version, suffix))

    return_or_fetch(key, handle, version, opts)
  end

  defp create_table_if_needed(:undefined),
    do: :ets.new(@table, [:set, :public, :named_table])

  defp create_table_if_needed(_), do: nil

  defp return_or_fetch([], handle, version, opts) do
    suffix = Keyword.get(opts, :suffix, "")
    public_key = Erebus.KMS.get_public_key(handle, version, opts)
    calculated_key = calculate_key(handle, version, suffix)

    :ets.insert(@table, {calculated_key, public_key})

    public_key
  end

  defp return_or_fetch([{_, key} | _], _handle, _version, _opts), do: key

  defp calculate_key(handle, version, suffix), do: {handle, version, suffix}
end
