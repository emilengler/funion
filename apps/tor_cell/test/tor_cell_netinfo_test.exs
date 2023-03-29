defmodule TorCellNetinfoTest do
  use ExUnit.Case
  doctest TorCell.Netinfo

  test "decodes a TorCell.Netinfo" do
    payload =
      <<42::32>> <> <<4, 4, 1, 1, 1, 1>> <> <<2>> <> <<4, 4, 2, 2, 2, 2>> <> <<6, 16, 1::8*16>>

    cell = TorCell.Netinfo.decode(payload)

    assert cell.time == DateTime.from_unix!(42)
    assert cell.otheraddr == [1, 1, 1, 1]
    assert length(cell.myaddrs) == 2

    assert hd(cell.myaddrs) == [2, 2, 2, 2]
    assert hd(tl(cell.myaddrs)) == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
  end

  test "decodes a TorCell.Netinfo with zero myaddrs" do
    payload = <<0::32>> <> <<4, 4, 1, 1, 1, 1>> <> <<0>>
    cell = TorCell.Netinfo.decode(payload)

    assert cell.time == DateTime.from_unix!(0)
    assert cell.otheraddr == [1, 1, 1, 1]
    assert cell.myaddrs == []
  end

  test "encodes a TorCell.Netinfo" do
    cell = %TorCell.Netinfo{
      time: DateTime.from_unix!(42),
      otheraddr: [1, 1, 1, 1],
      myaddrs: [[2, 2, 2, 2], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]]
    }

    assert TorCell.Netinfo.encode(cell) ==
             <<42::32>> <>
               <<4, 4, 1, 1, 1, 1>> <> <<2>> <> <<4, 4, 2, 2, 2, 2>> <> <<6, 16, 1::8*16>>
  end
end
