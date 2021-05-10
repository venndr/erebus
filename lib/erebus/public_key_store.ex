defmodule Erebus.PublicKeyStore do
  def init() do
    :ets.new(:erebus_public_key_store, [:set, :private, :named_table])
  end

  def get_key(handle, version, opts) do
    key = :ets.lookup(:erebus_public_key_store, calculate_key(handle, version))

    return_or_fetch(key, handle, version, opts)
  end

  defp return_or_fetch([], handle, version, opts) do
    public_key = Erebus.KMS.get_public_key(handle, version, opts)

    :ets.insert(:erebus_public_key_store, {calculate_key(handle, version), public_key})

    public_key
  end

  defp return_or_fetch([key | _], _handle, _version, _opts), do: key

  defp calculate_key(handle, version) when is_integer(version),
    do: calculate_key(handle, Integer.to_string(version))

  defp calculate_key(handle, version), do: handle <> "#" <> version
end
