# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Data do
  @enforce_keys [:data]
  defstruct data: nil

  @type t :: %TorCell.RelayCell.Data{data: binary()}

  @spec decode(binary()) :: t()
  def decode(data) do
    %TorCell.RelayCell.Data{data: data}
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    cell.data
  end
end
