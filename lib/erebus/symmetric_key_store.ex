defmodule Erebus.SymmetricKeyStore do
  def init() do
    :ets.new(:erebus_symmetric_key_store, [:set, :private, :named_table])
  end

  def get_key(encrypted, opts) do
    key = :ets.lookup(:erebus_symmetric_key_store, encrypted)

    return_or_fetch(key, encrypted, opts)
  end

  defp return_or_fetch([], encrypted, opts) do
    symmetric_key = Erebus.KMS.decrypt(encrypted, opts)

    :ets.insert(:erebus_symmetric_key_store, {encrypted, symmetric_key})

    symmetric_key
  end

  defp return_or_fetch([key | _], _handle, _version), do: key
end
