defprotocol Erebus.Encryption do
  @doc """
  Erebus.Encryption protocol lists the fields that need to be encrypted when encrypting a struct.
  """

  @spec encrypted_fields(t) :: list(atom())
  def encrypted_fields(value)
end
