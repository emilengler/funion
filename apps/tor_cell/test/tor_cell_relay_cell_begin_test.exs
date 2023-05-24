# SPDX-License-Identifier: ISC

defmodule TorCellRelayCellBeginTest do
  use ExUnit.Case
  doctest TorCell.RelayCell.Begin

  test "decodes a RELAY_BEGIN TorCell" do
    assert TorCell.RelayCell.Begin.decode("example.com:2022" <> <<0>> <> <<7::32>>) ==
             %TorCell.RelayCell.Begin{
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
    cell = %TorCell.RelayCell.Begin{
      host: "example.com",
      port: 2022,
      flags: %{
        ipv6_okay: true,
        ipv4_not_okay: false,
        ipv6_preferred: true
      }
    }

    assert TorCell.RelayCell.Begin.encode(cell) == "example.com:2022" <> <<0>> <> <<5::32>>
  end
end
