# SPDX-License-Identifier: ISC

defmodule TorCrypto.Digest do
  @moduledoc """
  Implements the running digest in a stateful fashion.
  """

  @type t :: :crypto.hash_state()

  @doc """
  Initializes the digest using a seed.
  """
  @spec init(binary()) :: t()
  def init(seed) do
    update(:crypto.hash_init(:sha), seed)
  end

  @doc """
  Updates the digest with new data.

  Returns the updated digest, obsoleting the old one.
  """
  @spec update(t(), binary()) :: t()
  def update(digest, data) do
    :crypto.hash_update(digest, data)
  end

  @doc """
  Returns a binary corresponding to the current SHA-1 hash of the digest.
  """
  @spec calculate(t()) :: binary()
  def calculate(digest) do
    :crypto.hash_final(digest)
  end
end
