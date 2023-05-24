# SPDX-License-Identifier: ISC

defmodule TorCellCreate2Test do
  use ExUnit.Case
  doctest TorCell.Create2

  test "decodes a CREATE2 TorCell" do
    assert TorCell.Create2.decode(<<0, 2, 0, 2, 42, 69>>) == %TorCell.Create2{
             type: :ntor,
             data: <<42, 69>>
           }
  end

  test "encodes a CREATE2 TorCell" do
    assert TorCell.Create2.encode(%TorCell.Create2{
             type: :ntor,
             data: <<42, 69>>
           }) == <<0, 2, 0, 2, 42, 69>>
  end
end
