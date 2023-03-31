defmodule TorCellVersionsTest do
  use ExUnit.Case
  doctest TorCell.Versions

  test "decodes a TorCell.Versions" do
    payload = <<1::16, 2::16, 2 ** 16 - 1::16>>

    assert TorCell.Versions.decode(payload) == %TorCell.Versions{
             versions: [1, 2, 2 ** 16 - 1]
           }
  end

  test "decodes an empty TorCell.Versions" do
    assert TorCell.Versions.decode(<<>>) == %TorCell.Versions{
             versions: []
           }
  end

  test "encodes a TorCell.Versions" do
    payload =
      TorCell.Versions.encode(%TorCell.Versions{
        versions: [1, 2, 2 ** 16 - 1]
      })

    assert payload == <<1::16, 2::16, 2 ** 16 - 1::16>>
  end
end
