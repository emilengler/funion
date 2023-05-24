# SPDX-License-Identifier: ISC

defmodule TorCell.Padding do
  defstruct padding: nil

  @doc """
  Decodes the payload of a PADDING TorCell into its internal representation.

  Returns a TorCell.Padding with padding set to the padding bytes.
  """
  def decode(payload) do
    # Just to be 100% sure ;-)
    <<padding::binary-size(509)>> = payload

    %TorCell.Padding{
      padding: padding
    }
  end

  @doc """
  Encodes a TorCell.Padding into a binary.

  Returns a binary corresponding to the payload of a PADDING TorCell.
  """
  def encode(cell) do
    <<cell.padding::binary-size(509)>>
  end
end
