defmodule TorCellRelayTest do
  use ExUnit.Case
  doctest TorCell.Relay

  test "decodes a RELAY TorCell" do
    assert TorCell.Relay.decode(<<1::509*8>>) == %TorCell.Relay{onion_skin: <<1::509*8>>}
  end

  test "encodes a RELAY TorCell" do
    assert TorCell.Relay.encode(%TorCell.Relay{onion_skin: <<1::509*8>>}) == <<1::509*8>>
  end
end
