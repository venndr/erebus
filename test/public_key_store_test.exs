defmodule Erebus.PublicKeyStoreTest do
  use ExUnit.Case, async: false

  import Mock

  test "fetching and refetching private key" do
    with_mock Erebus.KMS, get_public_key: fn handle, _, _ -> handle end do
      assert "handle1" == Erebus.PublicKeyStore.get_key("handle1", "1", [])
      assert "handle1" == Erebus.PublicKeyStore.get_key("handle1", "1", [])

      assert "handle2" == Erebus.PublicKeyStore.get_key("handle2", "1", [])
      assert "handle2" == Erebus.PublicKeyStore.get_key("handle2", "1", [])
    end
  end
end
