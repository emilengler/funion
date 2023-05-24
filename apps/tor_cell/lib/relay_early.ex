defmodule TorCell.RelayEarly do
  @moduledoc """
  Implements an **encrypted** RELAY TorCell.

  This is more of an intermediate representation between TorCell and
  TorCell.RelayCell.
  """
  defstruct onion_skin: nil

  @doc """
  Decodes the payload of a RELAY_EARLY TorCell into its internal representation.
  This function does not perform any sort of decryption.

  Returns a TorCell.RelayEarly with the onion_skin field being identical to the
  original payload of the TorCell.
  """
  def decode(payload) do
    %TorCell.RelayEarly{onion_skin: TorCell.Relay.decode(payload).onion_skin}
  end

  @doc """
  Encodes a TorCell.RelayEarly into a binary, without performing any sort encryption.

  Returns a binary corresponding to the payload of a RELAY_EARLY TorCell.
  """
  def encode(cell) do
    TorCell.Relay.encode(cell)
  end
end
