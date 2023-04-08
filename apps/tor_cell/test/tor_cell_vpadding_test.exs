defmodule TorCellVpaddingTest do
  use ExUnit.Case
  doctest TorCell.Vpadding

  test "decodes a VPADDING TorCell" do
    assert TorCell.Vpadding.decode(<<42, 69>>) == %TorCell.Vpadding{padding: <<42, 69>>}
  end

  test "encodes a VPADDING TorCell" do
    assert TorCell.Vpadding.encode(%TorCell.Vpadding{padding: <<42, 69>>}) == <<42, 69>>
  end
end
