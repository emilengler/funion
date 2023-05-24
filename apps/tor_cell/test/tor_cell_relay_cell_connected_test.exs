defmodule TorCellRelayCellConnectedTest do
  use ExUnit.Case
  doctest TorCell.RelayCell.Connected

  test "decodes a RELAY_CONNECTED IPv4 TorCell" do
    assert TorCell.RelayCell.Connected.decode(<<1, 1, 1, 1>> <> <<42::32>>) ==
             %TorCell.RelayCell.Connected{
               ip: {1, 1, 1, 1},
               ttl: 42
             }
  end

  test "encodes a RELAY_CONNECTED IPv4 TorCell" do
    cell = %TorCell.RelayCell.Connected{ip: {1, 1, 1, 1}, ttl: 42}
    assert TorCell.RelayCell.Connected.encode(cell) == <<1, 1, 1, 1, 42::32>>
  end

  test "decodes a RELAY_CONNECTED IPv6 TorCell" do
    assert TorCell.RelayCell.Connected.decode(<<0::32>> <> <<6>> <> <<69::128>> <> <<42::32>>) ==
             %TorCell.RelayCell.Connected{
               ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69},
               ttl: 42
             }
  end

  test "encodes a RELAY_CONNECTED IPv6 TorCell" do
    cell = %TorCell.RelayCell.Connected{
      ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69},
      ttl: 42
    }

    assert TorCell.RelayCell.Connected.encode(cell) == <<0::32, 6, 69::128, 42::32>>
  end
end
