# SPDX-License-Identifier: ISC

defmodule TorCrypto.OnionSkin do
  @doc """
  Decrypts an onion skin, layer by layer from a list of keys, as
  specified in 5.5.3 in `tor-spec.txt`.
  The onion skin is decrypted from the first to the last key.

  Returns a binary corresponding to the decrypted onion skin.
  """
  def decrypt(data, keys) when length(keys) > 0 do
    decrypt(:crypto.crypto_one_time(:aes_ctr, List.last(keys), <<0::128>>, data, false), tl(keys))
  end

  def decrypt(data, _) do
    data
  end

  @doc """
  Encrypts data to an onion skin, layer by layer from a list of keys, as
  specified in 5.5.2.1 in `tor-spec.txt`.
  The onion skin is created from the last to the first key.

  Returns a binary corresponding to the encrypted onion skin.
  """
  def encrypt(data, keys) when length(keys) > 0 do
    encrypted = :crypto.crypto_one_time(:aes_ctr, List.last(keys), <<0::128>>, data, true)
    encrypt(encrypted, Enum.take(keys, length(keys) - 1))
  end

  def encrypt(data, _) do
    data
  end
end
