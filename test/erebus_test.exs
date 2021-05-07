defmodule ErebusTest do
  use ExUnit.Case
  doctest Erebus

  test "greets the world" do
    assert Erebus.hello() == :world
  end

  defmodule EncryptedStuff do
    use Erebus.Encryption, fields: [:first, :second]

    defstruct [:first, :first_encrypted, :first_hash, :second, :second_encrypted, :second_hash]

    def changeset(stuff, attrs) do
      stuff
      |> cast(attrs, [
        :first
        :second
      ])
      |> Erebus.encrypt()
  end

  test "encrypting data" do
    model = %EncryptedStuff{first: "hello", second: "there"}
  end
end
