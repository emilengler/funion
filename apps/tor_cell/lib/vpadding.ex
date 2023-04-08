defmodule TorCell.Vpadding do
  defstruct padding: nil

  @doc """
  Decodes the payload of a VPADDING TorCell into its internal representation.

  Returns a TorCell.Vpadding with padding set to the padding bytes.
  """
  def decode(payload) do
    %TorCell.Vpadding{
      padding: payload
    }
  end

  @doc """
  Encodes a TorCell.Vpadding into a binary.

  Returns a binary corresponding to the payload of a VPADDING TorCell.
  """
  def encode(cell) do
    <<cell.padding>>
  end
end
