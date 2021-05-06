defmodule ErebusTest do
  use ExUnit.Case
  doctest Erebus

  test "greets the world" do
    assert Erebus.hello() == :world
  end
end
