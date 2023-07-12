# SPDX-License-Identifier: ISC

defmodule TorCellRelayCellEndTest do
  use ExUnit.Case
  doctest TorCell.RelayCell.End

  test "decodes a TorCell.RelayCell.End cell" do
    assert TorCell.RelayCell.End.decode(<<1>>) == %TorCell.RelayCell.End{reason: :misc}
  end

  test "encodes a TorCell.RelayCell.End cell" do
    assert TorCell.RelayCell.End.encode(%TorCell.RelayCell.End{reason: :misc}) == <<1>>
  end
end
