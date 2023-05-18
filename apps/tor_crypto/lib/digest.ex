defmodule TorCrypto.Digest do
  @moduledoc """
  Implements the running digest in a stateful fashion.
  """

  @doc """
  Initializes the context required for calculating the running digest.

  Returns the internal representation of the context.
  """
  def init(seed) do
    update(:crypto.hash_init(:sha), seed)
  end

  @doc """
  Updates the context with new data.

  Returns a new internal representation of the context, obsoleting the previous.
  """
  def update(context, data) do
    :crypto.hash_update(context, data)
  end

  @doc """
  Calculates the actual digest of the context.

  Returns a binary corresponding to the current digest of the context.
  """
  def calculate(context) do
    :crypto.hash_final(context)
  end
end
