defmodule TorCell.Relay do
  @moduledoc """
  Implements an **encrypted** RELAY TorCell.

  This is more of an intermediate representation between TorCell and
  TorCell.Relay.Unencrypted

  TODO: Consider renaming this to TorCell.Relay.Encrypted, although this
  may loose the semantic of its role as an intermediate layer.
  """
  defstruct onion_skin: nil

  @doc """
  Decodes the payload of a RELAY TorCell into its internal representation.
  This function does not perform any sort of decryption.

  Returns a TorCell.Relay with the onion_skin field being identical to the
  original payload of the TorCell.
  """
  def decode(payload) do
    <<payload::binary-size(509)>> = payload

    %TorCell.Relay{
      onion_skin: payload
    }
  end

  @doc """
  Encodes a TorCell.Relay into a binary, without performing any sort encryption.

  Returns a binary corresponding to the payload of a RELAY TorCell.
  """
  def encode(cell) do
    <<cell.onion_skin::binary-size(509)>>
  end
end
