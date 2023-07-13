# SPDX-License-Identifier: ISC

defmodule TorCell.Versions do
  @enforce_keys [:versions]
  defstruct versions: nil

  @type t :: %TorCell.Versions{versions: list()}

  @spec decode(binary()) :: t()
  def decode(payload) do
    %TorCell.Versions{
      versions:
        for <<x, y <- payload>> do
          <<z::16>> = <<x, y>>
          z
        end
    }
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    Enum.join(Enum.map(cell.versions, fn z -> <<z::16>> end))
  end
end
