# SPDX-License-Identifier: ISC

defmodule TorCell.Versions do
  defstruct versions: nil

  @doc """
  Decodes the payload of a VERSIONS TorCell into its internal representation.

  Returns a TorCell.Versions with versions being a list of all versions given
  in this cell.
  """
  def decode(payload) do
    %TorCell.Versions{
      versions:
        for <<x, y <- payload>> do
          <<z::16>> = <<x, y>>
          z
        end
    }
  end

  @doc """
  Encodes a TorCell.Versions into a binary.

  Returns a binary corresponding to the payload of a VERSIONS TorCell.
  """
  def encode(cell) do
    # TODO: Maybe an overflow check here?
    Enum.join(Enum.map(cell.versions, fn z -> <<z::16>> end))
  end
end
