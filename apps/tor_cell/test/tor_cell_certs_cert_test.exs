defmodule TorCellCertsCertTest do
  use ExUnit.Case
  doctest TorCell.Certs.Cert

  test "fetches a cert" do
    payload = <<4>> <> <<0, 2>> <> <<42, 69>>
    {cell, payload} = TorCell.Certs.Cert.fetch(payload)

    assert cell.type == :ed25519_id_signing
    assert cell.cert == <<42, 69>>
    assert payload == <<>>
  end

  test "fetches a cert with remaining data" do
    payload = <<4>> <> <<0, 1>> <> <<42, 69>>
    {cell, payload} = TorCell.Certs.Cert.fetch(payload)

    assert cell.type == :ed25519_id_signing
    assert cell.cert == <<42>>
    assert payload == <<69>>
  end

  test "encodes a cert" do
    cert = %TorCell.Certs.Cert{type: :ed25519_id_signing, cert: <<1, 2, 3>>}
    assert TorCell.Certs.Cert.encode(cert) == <<4, 0, 3, 1, 2, 3>>
  end
end
