# SPDX-License-Identifier: ISC

defmodule TorCrypto.OnionSkin do
  @doc """
  Initializes the AES-CTR stream cipher required for onion skins.

  Returns the internal representation of the stream.
  """
  def init(key, encrypt) do
    :crypto.crypto_init(:aes_128_ctr, key, <<0::128>>, encrypt)
  end

  @doc """
  Decrypts data by removing length(streams) onion skins from it.
  The decryption takes place from the first stream to the last.
  See section 5.5.3 in `tor-spec.txt`

  Returns a binary corresponding to the decrypted onion skin.
  """
  def decrypt(streams, data) when length(streams) > 0 do
    stream = hd(streams)
    decrypted = :crypto.crypto_update(stream, data) <> :crypto.crypto_final(stream)
    decrypt(tl(streams), decrypted)
  end

  def decrypt(_, data) do
    data
  end

  @doc """
  Encrypts data to an onion skin by adding length(streams) layers to it.
  The encryption takes place from the last stream to the first.
  See section 5.5.2.1 in `tor-spec.txt`
  """
  def encrypt(streams, data) when length(streams) > 0 do
    stream = List.last(streams)
    encrypted = :crypto.crypto_update(stream, data) <> :crypto.crypto_final(stream)
    encrypt(Enum.take(streams, length(streams) - 1), encrypted)
  end

  def encrypt(_, data) do
    data
  end
end
