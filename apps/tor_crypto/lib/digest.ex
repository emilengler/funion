# SPDX-License-Identifier: ISC

defmodule TorCrypto.Digest do
  @moduledoc """
  Implements the running digest in a stateful fashion.
  """
  defstruct state: nil

  @type t :: %TorCrypto.Digest{state: :crypto.hash_state()}

  @doc """
  Initializes the digest using a seed.
  """
  @spec init(binary()) :: t()
  def init(seed) do
    update(%TorCrypto.Digest{state: :crypto.hash_init(:sha)}, seed)
  end

  @doc """
  Updates the digest with new data.

  Returns the updated digest, obsoleting the old one.
  """
  @spec update(t(), binary()) :: t()
  def update(digest, data) do
    %TorCrypto.Digest{state: :crypto.hash_update(digest.state, data)}
  end

  @doc """
  Returns a binary corresponding to the current SHA-1 hash of the digest.
  """
  def calculate(digest) do
    :crypto.hash_final(digest.state)
  end
end
