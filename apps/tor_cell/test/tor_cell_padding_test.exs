# SPDX-License-Identifier: ISC

defmodule TorCellPaddingTest do
  use ExUnit.Case
  doctest TorCell.Padding

  test "decodes a PADDING TorCell" do
    assert TorCell.Padding.decode(<<1::509*8>>) == %TorCell.Padding{padding: <<1::509*8>>}
  end

  test "encodes a PADDING TorCell" do
    assert TorCell.Padding.encode(%TorCell.Padding{padding: <<1::509*8>>}) == <<1::509*8>>
  end
end
