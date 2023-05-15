defmodule TorCrypto.Handshake.Ntor do
  @doc """
  Generates the KEY_SEED value from the secret input.

  Returns a binary corresponding to the KEY_SEED value.
  """
  def key_seed(secret_input) do
    :crypto.mac(:hmac, :sha256, "ntor-curve25519-sha256-1:key_extract", secret_input)
  end

  @doc """
  Generates the verify value from the secret input.

  Returns a binary corresponding to the verify value.
  """
  def verify(secret_input) do
    :crypto.mac(:hmac, :sha256, "ntor-curve25519-sha256-1:verify", secret_input)
  end

  @doc """
  Generates the auth_input value from the secret input and other values.

  Returns a binary corresponding to the auth_input value.
  """
  def auth_input(secret_input, b, id, x, y) do
    verify(secret_input) <> id <> b <> y <> x <> "ntor-curve25519-sha256-1" <> "Server"
  end

  @doc """
  Generates n bytes from the KDF.

  Returns a binary corresponding to the first n bytes from the KDF.
  """
  def kdf(secret_input, n) do
    HKDF.derive(
      :sha256,
      secret_input,
      n,
      "ntor-curve25519-sha256-1:key_extract",
      "ntor-curve25519-sha256-1:key_expand"
    )
  end

  @doc """
  Derives the keys from the secret_input.

  Returns a TorCrypto.Handshake.Keys, containing the keys.
  """
  def derive_keys(secret_input) do
    k = kdf(secret_input, 72)
    <<df::binary-size(20), k::binary>> = k
    <<db::binary-size(20), k::binary>> = k
    <<kf::binary-size(16), k::binary>> = k
    <<kb::binary-size(16), _::binary>> = k

    %TorCrypto.Handshake.Keys{
      df: df,
      db: db,
      kf: kf,
      kb: kb
    }
  end
end
