# SPDX-License-Identifier: ISC

defmodule TorCellNetinfoTest do
  use ExUnit.Case
  doctest TorCell.Netinfo

  test "decodes a TorCell.Netinfo cell" do
    payload = <<42::32, 4, 4, 1, 1, 1, 1, 2, 4, 4, 2, 2, 2, 2, 6, 16, 1::16*8>>

    assert TorCell.Netinfo.decode(payload) == %TorCell.Netinfo{
             time: DateTime.from_unix!(42),
             otheraddr: {1, 1, 1, 1},
             myaddrs: [{2, 2, 2, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}]
           }
  end

  test "decodes a TorCell.Netinfo cell with zero myaddrs" do
    assert TorCell.Netinfo.decode(<<0::32, 4, 4, 1, 1, 1, 1, 0>>) == %TorCell.Netinfo{
             time: DateTime.from_unix!(0),
             otheraddr: {1, 1, 1, 1},
             myaddrs: []
           }
  end

  test "encodes a TorCell.Netinfo cell" do
    cell = %TorCell.Netinfo{
      time: DateTime.from_unix!(42),
      otheraddr: {1, 1, 1, 1},
      myaddrs: [{2, 2, 2, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}]
    }

    assert TorCell.Netinfo.encode(cell) ==
             <<42::32, 4, 4, 1, 1, 1, 1, 2, 4, 4, 2, 2, 2, 2, 6, 16, 1::16*8>>
  end
end
