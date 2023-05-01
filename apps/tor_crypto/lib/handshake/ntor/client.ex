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
    :crypto.compute_key(:ecdh, y, x_sk, :x25519) <>
      :crypto.compute_key(:ecdh, b, x_sk, :x25519) <>
      id <>
      b <>
      x_pk <>
      y <>
      "ntor-curve25519-sha256-1"
  end
end
