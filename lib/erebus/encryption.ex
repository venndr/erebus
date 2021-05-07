defprotocol Erebus.Encryption do
  @spec encrypted_fields(t) :: list(atom())
  def encrypted_fields(value)
end
