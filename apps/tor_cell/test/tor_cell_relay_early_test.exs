# SPDX-License-Identifier: ISC

defmodule TorCellRelayEarlyTest do
  use ExUnit.Case
  doctest TorCell.RelayEarly

  test "decodes a RELAY_EARLY cell" do
    assert TorCell.RelayEarly.decode(<<1::509*8>>) == %TorCell.RelayEarly{
             onion_skin: <<1::509*8>>
           }
  end

  test "encodes a RELAY_EARLY cell" do
    assert TorCell.Relay.encode(%TorCell.RelayEarly{onion_skin: <<1::509*8>>}) == <<1::509*8>>
  end
end
