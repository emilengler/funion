defmodule TorCellRelayBeginTest do
  use ExUnit.Case
  doctest TorCell.Relay.Begin

  test "decodes a RELAY_BEGIN TorCell" do
    assert TorCell.Relay.Begin.decode("example.com:2022" <> <<0>> <> <<7::32>>) ==
             %TorCell.Relay.Begin{
               host: "example.com",
               port: 2022,
               flags: %{
                 ipv6_okay: true,
                 ipv4_not_okay: true,
                 ipv6_preferred: true
               }
             }
  end

  test "encodes a RELAY_BEGIN TorCell" do
    cell = %TorCell.Relay.Begin{
      host: "example.com",
      port: 2022,
      flags: %{
        ipv6_okay: true,
        ipv4_not_okay: false,
        ipv6_preferred: true
      }
    }

    assert TorCell.Relay.Begin.encode(cell) == "example.com:2022" <> <<0>> <> <<5::32>>
  end
end
