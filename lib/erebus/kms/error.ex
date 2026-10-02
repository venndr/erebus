defmodule Erebus.KMS.Error do
  @moduledoc """
  Raised when a KMS backend call fails, after retrying a transient error.

  `reason` is the backend's error, with HTTP failures reduced to
  `{:http_status, status}` so response bodies and headers stay out of the message.
  """

  defexception [:operation, :reason]

  @impl true
  def message(%{operation: operation, reason: reason}),
    do: "KMS #{operation} failed: #{inspect(reason)}"
end
