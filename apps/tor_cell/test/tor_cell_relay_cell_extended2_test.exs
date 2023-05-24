# SPDX-License-Identifier: ISC

defmodule TorCellRelayCellExtended2Test do
  use ExUnit.Case
  doctest TorCell.RelayCell.Extended2

  test "decodes a RELAY_EXTENDED2 TorCell" do
    assert TorCell.RelayCell.Extended2.decode(<<0, 2, 42, 69>>) == %TorCell.RelayCell.Extended2{
             data: <<42, 69>>
           }
  end

  test "encodes a RELAY_EXTENDED2 TorCell" do
    assert TorCell.RelayCell.Extended2.encode(%TorCell.RelayCell.Extended2{
             data: <<42, 69>>
           }) == <<0, 2, 42, 69>>
  end
end
