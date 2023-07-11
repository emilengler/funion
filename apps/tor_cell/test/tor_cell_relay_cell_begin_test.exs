# SPDX-License-Identifier: ISC

defmodule TorCellRelayCellBeginTest do
  use ExUnit.Case
  doctest TorCell.RelayCell.Begin

  test "decodes a TorCell.RelayCell.Begin cell" do
    assert TorCell.RelayCell.Begin.decode("example.com:80" <> <<0, 5::32>>) ==
             %TorCell.RelayCell.Begin{host: "example.com", port: 80}
  end

  test "encodes a TorCell.RelayCell.Begin cell" do
    assert TorCell.RelayCell.Begin.encode(%TorCell.RelayCell.Begin{host: "example.com", port: 80}) ==
             "example.com:80" <> <<0, 5::32>>
  end
end
