defmodule TorCellAuthenticateRsaSha256Tlssecret do
  use ExUnit.Case
  doctest TorCell.Authenticate.RsaSha256Tlssecret

  test "decodes a TorCell.Authenticate.RsaSha256Tlssecret" do
    payload =
      "AUTH0001" <>
        <<0::8*32>> <>
        <<1::8*32>> <>
        <<2::8*32>> <> <<3::8*32>> <> <<4::8*32>> <> <<5::8*32>> <> <<6::8*24>> <> <<42, 69>>

    auth = TorCell.Authenticate.RsaSha256Tlssecret.decode(payload)

    assert auth == %TorCell.Authenticate.RsaSha256Tlssecret{
      cid: <<0::8*32>>,
      sid: <<1::8*32>>,
      slog: <<2::8*32>>,
      clog: <<3::8*32>>,
      scert: <<4::8*32>>,
      tlssecrets: <<5::8*32>>,
      rand: <<6::8*24>>,
      sig: <<42, 69>>
    }
  end

  test "encodes a TorCell.Authenticate.RsaSha256Tlssecret" do
    auth = %TorCell.Authenticate.RsaSha256Tlssecret{
      cid: <<0::8*32>>,
      sid: <<1::8*32>>,
      slog: <<2::8*32>>,
      clog: <<3::8*32>>,
      scert: <<4::8*32>>,
      tlssecrets: <<5::8*32>>,
      rand: <<6::8*24>>,
      sig: <<42, 69>>
    }

    assert TorCell.Authenticate.RsaSha256Tlssecret.encode(auth) ==
             "AUTH0001" <>
               <<0::8*32>> <>
               <<1::8*32>> <>
               <<2::8*32>> <>
               <<3::8*32>> <> <<4::8*32>> <> <<5::8*32>> <> <<6::8*24>> <> <<42, 69>>
  end
end
