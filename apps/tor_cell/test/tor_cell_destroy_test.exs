# SPDX-License-Identifier: ISC

defmodule TorCellDestroyTest do
  use ExUnit.Case
  doctest TorCell.Destroy

  test "decodes a DESTROY TorCell" do
    assert TorCell.Destroy.decode(<<0::509*8>>) == %TorCell.Destroy{reason: :none}
  end

  test "encodes a DESTROY TorCell" do
    assert TorCell.Destroy.encode(%TorCell.Destroy{reason: :none}) == <<0::509*8>>
  end
end
