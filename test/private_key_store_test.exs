defmodule Erebus.PrivateKeyStoreTest do
  use ExUnit.Case, async: false

  import Mock

  test "fetching and refetching private key" do
    with_mock Erebus.KMS, get_private_key: fn handle, _, _ -> handle end do
      assert "handle1" == Erebus.PrivateKeyStore.get_key("handle1", "1", [])
      assert "handle1" == Erebus.PrivateKeyStore.get_key("handle1", "1", [])

      assert "handle2" == Erebus.PrivateKeyStore.get_key("handle2", "1", [])
      assert "handle2" == Erebus.PrivateKeyStore.get_key("handle2", "1", [])
    end
  end
end
