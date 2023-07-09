# SPDX-License-Identifier: ISC

defmodule TorCellCreated2Test do
  use ExUnit.Case
  doctest TorCell.Created2

  test "decodes a TorCell.Created2 cell" do
    assert TorCell.Created2.decode(<<0, 2, 42, 69>>) == %TorCell.Created2{hdata: <<42, 69>>}
  end

  test "encodes a TorCell.Created2 cell" do
    assert TorCell.Created2.encode(%TorCell.Created2{hdata: <<42, 69>>}) == <<0, 2, 42, 69>>
  end
end
