# SPDX-License-Identifier: ISC

defmodule TorCrypto.OnionStream do
  @moduledoc """
  Implements functions for adding and removing onion skins to arbitrary data,
  using a stream cipher.
  """
  @type t :: :crypto.crypto_state()

  @doc """
  Initializes the onion stream cipher with an AES-128 key.
  """
  @spec init(binary(), boolean()) :: t()
  def init(key, encrypt) do
    :crypto.crypto_init(:aes_128_ctr, key, <<0::128>>, encrypt)
  end

  @doc """
  Decrypts `data` by removing `length(streams)` onion skins from it.
  The decryption takes place from the first stream to the last.
  See section 5.5.3 in `tor-spec.txt`.
  """
  @spec decrypt(list(t()), binary()) :: binary()
  def decrypt(streams, data) when length(streams) > 0 do
    decrypted = :crypto.crypto_update(hd(streams), data)
    decrypt(tl(streams), decrypted)
  end

  def decrypt(_, data) do
    data
  end

  @doc """
  Encrypts `data` by adding `length(streams)` onion skins to it.
  The encryption takes place from the last stream to the first.
  See section 5.5.2.1 in `tor-spec.txt`.
  """
  @spec encrypt(list(t()), binary()) :: binary()
  def encrypt(streams, data) when length(streams) > 0 do
    encrypted = :crypto.crypto_update(List.last(streams), data)
    encrypt(Enum.take(streams, length(streams) - 1), encrypted)
  end

  def encrypt(_, data) do
    data
  end
end
