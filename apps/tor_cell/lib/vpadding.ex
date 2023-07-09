# SPDX-License-Identifier: ISC

defmodule TorCell.Vpadding do
  @enforce_keys [:padding]
  defstruct padding: nil

  @type t :: %TorCell.Vpadding{padding: binary()}

  @spec decode(binary()) :: TorCell.Vpadding
  def decode(payload) do
    %TorCell.Vpadding{padding: payload}
  end

  @spec encode(TorCell.Vpadding) :: binary()
  def encode(cell) do
    cell.padding
  end
end
