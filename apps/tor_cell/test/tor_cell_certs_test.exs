defmodule TorCellCertsTest do
  use ExUnit.Case
  doctest TorCell.Certs

  test "decodes a CERTS TorCell" do
    payload = <<2>> <> <<1, 0, 1, 42>> <> <<2, 0, 2, 42, 69>>

    assert TorCell.Certs.decode(payload) == %TorCell.Certs{
             certs: [
               %TorCell.Certs.Cert{type: :rsa_link, cert: <<42>>},
               %TorCell.Certs.Cert{type: :rsa_id, cert: <<42, 69>>}
             ]
           }
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
