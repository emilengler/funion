defmodule TorCellTest do
  use ExUnit.Case
  doctest TorCell

  test "encodes a fixed-length cell (4-byte circ_id)" do
    data =
      TorCell.encode(
        %TorCell{
          circ_id: 2 ** 32 - 1,
          cmd: :padding,
          payload: %TorCell.Padding{padding: <<0::509*8>>}
        },
        4
      )

    assert data == <<2 ** 32 - 1::32>> <> <<0>> <> <<0::509*8>>
  end

  test "encodes a variable-length cell (2-byte circ_id)" do
    data =
      TorCell.encode(
        %TorCell{
          circ_id: 1,
          cmd: :vpadding,
          payload: %TorCell.Vpadding{padding: <<1, 2, 3>>}
        },
        2
      )

    assert data == <<1::16>> <> <<128>> <> <<3::16>> <> <<1, 2, 3>>
  end

  test "fetches a fixed-length cell (4-byte circ_id)" do
    data = <<2 ** 32 - 1::32>> <> <<0>> <> <<0::509*8>> <> <<42, 42, 42>>
    {cell, data} = TorCell.fetch(data, 4)

    assert cell == %TorCell{
             circ_id: 2 ** 32 - 1,
             cmd: :padding,
             payload: %TorCell.Padding{padding: <<0::509*8>>}
           }

    assert data == <<42, 42, 42>>
  end

  test "fetches a variable-length cell (2-byte circ_id)" do
    data =
      <<255::16>> <> <<7>> <> <<10::16>> <> <<1::16, 2::16, 3::16, 4::16, 5::16>> <> <<1, 2, 3>>

    {cell, data} = TorCell.fetch(data, 2)

    assert cell == %TorCell{
             circ_id: 255,
             cmd: :versions,
             payload: %TorCell.Versions{versions: [1, 2, 3, 4, 5]}
           }

    assert data == <<1, 2, 3>>
  end
end
