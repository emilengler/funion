defmodule TorCellCreated2Test do
  use ExUnit.Case
  doctest TorCell.Created2

  test "decodes a CREATED2 TorCell" do
    assert TorCell.Created2.decode(<<0, 2, 42, 69>>) == %TorCell.Created2{
             data: <<42, 69>>
           }
  end

  test "encodes a CREATED2 TorCell" do
    assert TorCell.Created2.encode(%TorCell.Created2{
             data: <<42, 69>>
           }) == <<0, 2, 42, 69>>
  end
end
