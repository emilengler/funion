# SPDX-License-Identifier: ISC

defmodule TorCellRelayCellEndTest do
  use ExUnit.Case
  doctest TorCell.RelayCell.End

  test "decodes a RELAY_END TorCell" do
    assert TorCell.RelayCell.End.decode(<<1>>) == %TorCell.RelayCell.End{reason: :misc}
  end

  test "decodes a RELAY_END TorCell with an IPv4 exit policy" do
    assert TorCell.RelayCell.End.decode(<<4, 1, 1, 1, 1, 42::32>>) == %TorCell.RelayCell.End{
             reason: :exitpolicy,
             ip: {1, 1, 1, 1},
             ttl: 42
           }
  end

  test "decodes a RELAY_END TorCell with an IPv6 exit policy" do
    assert TorCell.RelayCell.End.decode(<<4, 1::128, 69::32>>) == %TorCell.RelayCell.End{
             reason: :exitpolicy,
             ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
             ttl: 69
           }
  end

  test "encodes a RELAY_END TorCell" do
    cell = %TorCell.RelayCell.End{reason: :misc}
    assert TorCell.RelayCell.End.encode(cell) == <<1>>
  end

  test "encodes a RELAY_END TorCell with an IPv4 exit policy" do
    cell = %TorCell.RelayCell.End{reason: :exitpolicy, ip: {2, 2, 2, 2}, ttl: 0}
    assert TorCell.RelayCell.End.encode(cell) == <<4, 2, 2, 2, 2, 0, 0, 0, 0>>
  end

  test "encodes a RELAY_END TorCell with an IPv6 exit policy" do
    cell = %TorCell.RelayCell.End{
      reason: :exitpolicy,
      ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
      ttl: 42
    }

    assert TorCell.RelayCell.End.encode(cell) == <<4, 1::128, 42::32>>
  end
end
