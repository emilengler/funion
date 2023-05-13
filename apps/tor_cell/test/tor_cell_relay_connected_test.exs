defmodule TorCellRelayConnectedTest do
  use ExUnit.Case
  doctest TorCell.Relay.Connected

  test "decodes a RELAY_CONNECTED IPv4 TorCell" do
    assert TorCell.Relay.Connected.decode(<<1, 1, 1, 1>> <> <<42::32>>) ==
             %TorCell.Relay.Connected{
               ip: {1, 1, 1, 1},
               ttl: 42
             }
  end

  test "encodes a RELAY_CONNECTED IPv4 TorCell" do
    cell = %TorCell.Relay.Connected{ip: {1, 1, 1, 1}, ttl: 42}
    assert TorCell.Relay.Connected.encode(cell) == <<1, 1, 1, 1, 42::32>>
  end

  test "decodes a RELAY_CONNECTED IPv6 TorCell" do
    assert TorCell.Relay.Connected.decode(<<0::32>> <> <<6>> <> <<69::128>> <> <<42::32>>) ==
             %TorCell.Relay.Connected{
               ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69},
               ttl: 42
             }
  end

  test "encodes a RELAY_CONNECTED IPv6 TorCell" do
    cell = %TorCell.Relay.Connected{
      ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69},
      ttl: 42
    }

    assert TorCell.Relay.Connected.encode(cell) == <<0::32, 6, 69::128, 42::32>>
  end
end
