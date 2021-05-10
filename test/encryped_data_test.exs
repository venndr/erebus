defmodule Erebus.EncryptedDataTest do
  use ExUnit.Case

  test ".cast_if_needed with struct" do
    struct = %Erebus.EncryptedData{}

    assert struct == Erebus.EncryptedData.cast_if_needed(struct)
  end

  test ".cast_if_needed with map" do
    struct = %Erebus.EncryptedData{encrypted_dek: "anyxxx", handle: "handle", version: "version"}

    assert struct ==
             Erebus.EncryptedData.cast_if_needed(%{
               "encrypted_dek" => "anyxxx",
               "handle" => "handle",
               "version" => "version"
             })
  end
end
