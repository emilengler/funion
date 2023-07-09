# SPDX-License-Identifier: ISC

defmodule TorCell.Padding do
  @enforce_keys [:padding]
  defstruct padding: nil

  @type t :: %TorCell.Padding{padding: binary()}

  @spec decode(binary()) :: TorCell.Padding
  def decode(payload) do
    <<padding::binary-size(509)>> = payload
    %TorCell.Padding{padding: padding}
  end

  @spec encode(TorCell.Padding) :: binary()
  def encode(cell) do
    <<cell.padding::binary-size(509)>>
  end
end
