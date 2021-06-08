defprotocol Erebus.Encryption do
  @doc "Erebus.Encryption protocol lists field that needs to be encrypted while encrypting given struct."
  @spec encrypted_fields(t) :: list(atom())
  def encrypted_fields(value)
end
