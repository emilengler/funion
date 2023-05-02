defmodule TorCrypto.OnionSkin do
  @doc """
  Decrypts an onion skin layer by layer from a list of keys.
  The onion skin is decrypted by the keys in the list from last to first.

  Returns a binary corresponding to the decrypted onion skin.
  """
  def decrypt(data, keys) when length(keys) > 0 do
    decrypt(
      :crypto.crypto_one_time_aead(:aes_128_gcm, List.last(keys), <<0>>, data, <<>>, false),
      Enum.take(keys, length(keys) - 1)
    )
  end

  def decrypt(data, _) do
    data
  end

  @doc """
  Encrypts data to an onion skin layer by layer from a list of keys.
  The onion skin is encrpyted by the keys in the list from first to last.

  Returns a binary corresponding to the encrypted onion skins.
  """
  def encrypt(data, keys) when length(keys) > 0 do
    encrypt(
      :crypto.crypto_one_time_aead(:aes_128_gcm, hd(keys), <<0>>, data, <<>>, true),
      Enum.take(keys, tl(keys))
    )
  end

  def encrypt(data, _) do
    data
  end
end
