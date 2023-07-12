# SPDX-License-Identifier: ISC

defmodule TorCellTest do
  use ExUnit.Case
  doctest TorCell

  test "fetches a fixed-length TorCell with additional data" do
    data = <<42::32, 0, 42::509*8, 42, 69>>
    {cell, remaining} = TorCell.fetch(data)

    assert cell == %TorCell{
             circ_id: 42,
             cmd: :padding,
             payload: TorCell.Padding.decode(<<42::509*8>>)
           }

    assert remaining == <<42, 69>>
  end

  test "fetches a fixed-length TorCell with additional data (2-byte circ_id)" do
    data = <<42::16, 0, 42::509*8, 42, 69>>
    {cell, remaining} = TorCell.fetch(data, 2)

    assert cell == %TorCell{
             circ_id: 42,
             cmd: :padding,
             payload: TorCell.Padding.decode(<<42::509*8>>)
           }

    assert remaining == <<42, 69>>
  end

  test "fetches a variable-length TorCell with additional data" do
    data = <<0::32, 128, 69::16, 42::69*8, 42, 69>>
    {cell, remaining} = TorCell.fetch(data)

    assert cell == %TorCell{
             circ_id: 0,
             cmd: :vpadding,
             payload: TorCell.Vpadding.decode(<<42::69*8>>)
           }

    assert remaining == <<42, 69>>
  end

  test "encodes a fixed-length TorCell" do
    cell = %TorCell{
      circ_id: 42,
      cmd: :padding,
      payload: TorCell.Padding.decode(<<42::509*8>>)
    }

    assert TorCell.encode(cell) == <<42::32, 0, 42::509*8>>
  end

  test "encodes a fixed-length TorCell (2-byte circ_id)" do
    cell = %TorCell{
      circ_id: 42,
      cmd: :padding,
      payload: TorCell.Padding.decode(<<42::509*8>>)
    }

    assert TorCell.encode(cell, 2) == <<42::16, 0, 42::509*8>>
  end

  test "encodes a variable-length TorCell" do
    cell = %TorCell{
      circ_id: 0,
      cmd: :vpadding,
      payload: TorCell.Vpadding.decode(<<42::69*8>>)
    }

    assert TorCell.encode(cell, 4) == <<0::32, 128, 69::16, 42::69*8>>
  end
end
