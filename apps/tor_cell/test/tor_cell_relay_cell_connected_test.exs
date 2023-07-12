# SPDX-License-Identifier: ISC

defmodule TorCellRelayCellConnectedTest do
  use ExUnit.Case
  doctest TorCell.RelayCell.Connected

  test "decodes a TorCell.RelayCell.Connected IPv4 cell" do
    assert TorCell.RelayCell.Connected.decode(<<1, 1, 1, 1, 42::32>>) ==
             %TorCell.RelayCell.Connected{ip: {1, 1, 1, 1}, ttl: 42}
  end

  test "decodes a TorCell.RelayCell.Connected IPv6 cell" do
    assert TorCell.RelayCell.Connected.decode(<<0::32, 6, 69::128, 42::32>>) ==
             %TorCell.RelayCell.Connected{
               ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69},
               ttl: 42
             }
  end

  test "encodes a TorCell.RelayCell.Connected IPv4 cell" do
    assert TorCell.RelayCell.Connected.encode(%TorCell.RelayCell.Connected{
             ip: {1, 1, 1, 1},
             ttl: 42
           }) == <<1, 1, 1, 1, 42::32>>
  end

  test "encodes a TorCell.RelayCell.Connected IPv6 cell" do
    assert TorCell.RelayCell.Connected.encode(%TorCell.RelayCell.Connected{
             ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69},
             ttl: 42
           }) == <<0::32, 6, 69::128, 42::32>>
  end
end
