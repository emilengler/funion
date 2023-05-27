# SPDX-License-Identifier: ISC

defmodule TorCellRelayCellDataTest do
  use ExUnit.Case
  doctest TorCell.RelayCell.Data

  test "decodes a RELAY_DATA TorCell" do
    assert TorCell.RelayCell.Data.decode(<<42, 69>>) == %TorCell.RelayCell.Data{data: <<42, 69>>}
  end

  test "encodes a RELAY_DATA TorCell" do
    assert TorCell.RelayCell.Data.encode(%TorCell.RelayCell.Data{data: <<42, 69>>}) == <<42, 69>>
  end
end
