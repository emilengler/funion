defmodule TorCrypto.Handshake.Ntor.Client do
  @doc """
  Generates the temporary client-side key pair.

  Returns a tuple containing the temporary pubkey and the temporary secret key.
  """
  def stage1() do
    :crypto.generate_key(:ecdh, :x25519, :undefined)
  end

  @doc """
  Generates the client-side handshake.

  Returns a binary corresponding to the client-side handshake.
  """
  def stage2(b, id, x_pk) do
    id <> b <> x_pk
  end

  @doc """
  Generates the shared secret from the server's response to the stage1 handshake.

  Returns a binary corresponding to the secret input.
  """
  def stage3(b, id, x_pk, x_sk, y) do
    # TODO: Remove the boilerplate
    # The cryptographic keys as real integers
    <<b::integer-size(32)-unit(8)>> = b
    <<id::integer-size(20)-unit(8)>> = id
    <<x_pk::integer-size(32)-unit(8)>> = x_pk
    <<x_sk::integer-size(32)-unit(8)>> = x_sk
    <<y::integer-size(32)-unit(8)>> = y

    :binary.encode_unsigned(y * x_sk) <>
      :binary.encode_unsigned(b * x_sk) <>
      :binary.encode_unsigned(id) <>
      :binary.encode_unsigned(b) <>
      :binary.encode_unsigned(x_pk) <>
      :binary.encode_unsigned(y) <>
      "ntor-curve25519-sha256-1"
  end
end
