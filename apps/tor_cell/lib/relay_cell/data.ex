# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Data do
  defstruct data: nil

  # TODO: Document this
  def decode(data) do
    %TorCell.RelayCell.Data{data: data}
  end

  # TODO: Document this
  def encode(cell) do
    cell.data
  end
end
