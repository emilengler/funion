defmodule TorCertRsaEd25519Test do
  use ExUnit.Case
  doctest TorCert.RsaEd25519

  test "fetches a TorCert.RsaEd25519" do
    data =
      <<0::8*32>> <>
        <<0::32>> <>
        <<32>> <>
        <<0::8*64>>

    {cert, data} = TorCert.RsaEd25519.fetch(data)

    assert cert == %TorCert.RsaEd25519{
             ed25519_key: <<0::32*8>>,
             expiration_date: DateTime.from_unix!(0),
             signature: <<0::32*8>>
           }

    assert data == <<0::32*8>>
  end

  test "encodes a TorCert.RsaEd25519" do
    cert = %TorCert.RsaEd25519{
      ed25519_key: <<0::32*8>>,
      expiration_date: DateTime.from_unix!(0),
      signature: <<0::32*8>>
    }

    assert TorCert.RsaEd25519.encode(cert) == <<0::8*32>> <> <<0::32>> <> <<32>> <> <<0::8*32>>
  end
end
