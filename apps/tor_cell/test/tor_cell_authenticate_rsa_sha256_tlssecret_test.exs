defmodule TorCellAuthenticateRsaSha256Tlssecret do
  use ExUnit.Case
  doctest TorCell.Authenticate.RsaSha256Tlssecret

  test "decodes a TorCell.Authenticate.RsaSha256Tlssecret" do
    payload =
      "AUTH0001" <>
        <<0::8*32>> <>
        <<0::8*32>> <>
        <<0::8*32>> <> <<0::8*32>> <> <<0::8*32>> <> <<0::8*32>> <> <<0::8*24>> <> <<42, 69>>

    auth = TorCell.Authenticate.RsaSha256Tlssecret.decode(payload)

    assert auth.cid == <<0::8*32>>
    assert auth.sid == <<0::8*32>>
    assert auth.slog == <<0::8*32>>
    assert auth.clog == <<0::8*32>>
    assert auth.scert == <<0::8*32>>
    assert auth.tlssecrets == <<0::8*32>>
    assert auth.rand == <<0::8*24>>
    assert auth.sig == <<42, 69>>
  end

  test "encodes a TorCell.Authenticate.RsaSha256Tlssecret" do
    auth = %TorCell.Authenticate.RsaSha256Tlssecret{
      cid: <<0::8*32>>,
      sid: <<0::8*32>>,
      slog: <<0::8*32>>,
      clog: <<0::8*32>>,
      scert: <<0::8*32>>,
      tlssecrets: <<0::8*32>>,
      rand: <<0::8*24>>,
      sig: <<42, 69>>
    }

    assert TorCell.Authenticate.RsaSha256Tlssecret.encode(auth) ==
             "AUTH0001" <>
               <<0::8*32>> <>
               <<0::8*32>> <>
               <<0::8*32>> <>
               <<0::8*32>> <> <<0::8*32>> <> <<0::8*32>> <> <<0::8*24>> <> <<42, 69>>
  end
end
