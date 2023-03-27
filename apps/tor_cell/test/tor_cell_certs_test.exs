defmodule TorCellCertsTest do
  use ExUnit.Case
  doctest TorCell.Certs

  test "decodes a CERTS TorCell" do
    payload = <<2>> <> <<1, 0, 1, 42>> <> <<2, 0, 2, 42, 69>>
    cell = TorCell.Certs.decode(payload)

    assert length(cell.certs) == 2

    assert hd(cell.certs).type == :rsa_link
    assert hd(cell.certs).cert == <<42>>

    assert hd(tl(cell.certs)).type == :rsa_id
    assert hd(tl(cell.certs)).cert == <<42, 69>>
  end

  test "encodes a CERTS TorCell" do
    cell = %TorCell.Certs{
      certs: [
        %TorCell.Certs.Cert{type: :rsa_link, cert: <<42>>},
        %TorCell.Certs.Cert{type: :rsa_id, cert: <<42, 69>>}
      ]
    }

    assert TorCell.Certs.encode(cell) == <<2>> <> <<1, 0, 1, 42>> <> <<2, 0, 2, 42, 69>>
  end
end
