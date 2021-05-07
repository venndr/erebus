defmodule Erebus.PublicKeyStore do
  use Agent

  def start_link(_) do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  def get_key(handle, version) do
    key = Agent.get(__MODULE__, fn state -> Map.get(state, calculate_key(handle, version)) end)
    return_or_fetch(key, handle, version)
  end

  defp return_or_fetch(nil, handle, version) do
    public_key = Erebus.KMS.get_public_key(handle, version)

    Agent.update(__MODULE__, fn state ->
      Map.put(state, calculate_key(handle, version), public_key)
    end)

    public_key
  end

  defp return_or_fetch(key, _handle, _version), do: key

  defp calculate_key(handle, version) when is_integer(version),
    do: calculate_key(handle, Integer.to_string(version))

  defp calculate_key(handle, version), do: handle <> "#" <> version
end
