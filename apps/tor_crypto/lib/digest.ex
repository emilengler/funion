defmodule TorCrypto.Digest do
  @moduledoc """
  Implements the running digest in a stateful fashion.
  """

  @doc """
  Initializes the state required for calculating the running digest.

  Returns the internal representation of the state.
  """
  def init(seed) do
    update(:crypto.hash_init(:sha), seed)
  end

  @doc """
  Updates the state with new data.

  Returns a new internal representation of the state, obsoleting the previous.
  """
  def update(state, data) do
    :crypto.hash_update(state, data)
  end

  @doc """
  Calculates the actual digest of the state.

  Returns a binary corresponding to the current digest of the state.
  """
  def calculate(state) do
    :crypto.hash_final(state)
  end
end
