# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Data do
  @enforce_keys [:data]
  defstruct data: nil

  @type t :: %TorCell.RelayCell{data: binary()}

  @spec decode(binary()) :: TorCell.RelayCell.Data
  def decode(data) do
    %TorCell.RelayCell.Data{data: data}
  end

  @spec encode(TorCell.RelayCell.Data) :: binary()
  def encode(cell) do
    cell.data
  end
end
