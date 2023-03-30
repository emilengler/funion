defmodule TorCellAuthenticateEd25519Sha256Rfc5705Test do
  use ExUnit.Case
  doctest TorCell.Authenticate.Ed25519Sha256Rfc5705

  test "decodes a TorCell.Authenticate.Ed25519Sha256Rfc5705" do
    payload =
      "AUTH0003" <>
        <<0::8*32>> <>
        <<1::8*32>> <>
        <<2::8*32>> <>
        <<3::8*32>> <>
        <<4::8*32>> <>
        <<5::8*32>> <>
        <<6::8*32>> <>
        <<7::8*32>> <>
        <<8::8*24>> <>
        <<42, 69>>

    assert TorCell.Authenticate.Ed25519Sha256Rfc5705.decode(payload) ==
             %TorCell.Authenticate.Ed25519Sha256Rfc5705{
               cid: <<0::8*32>>,
               sid: <<1::8*32>>,
               cid_ed: <<2::8*32>>,
               sid_ed: <<3::8*32>>,
               slog: <<4::8*32>>,
               clog: <<5::8*32>>,
               scert: <<6::8*32>>,
               tlssecrets: <<7::8*32>>,
               rand: <<8::8*24>>,
               sig: <<42, 69>>
             }
  end

  test "encodes a TorCell.Authenticate.Ed25519Sha256Rfc5705" do
    auth = %TorCell.Authenticate.Ed25519Sha256Rfc5705{
      cid: <<0::8*32>>,
      sid: <<1::8*32>>,
      cid_ed: <<2::8*32>>,
      sid_ed: <<3::8*32>>,
      slog: <<4::8*32>>,
      clog: <<5::8*32>>,
      scert: <<6::8*32>>,
      tlssecrets: <<7::8*32>>,
      rand: <<8::8*24>>,
      sig: <<42, 69>>
    }

    assert TorCell.Authenticate.Ed25519Sha256Rfc5705.encode(auth) ==
             "AUTH0003" <>
               <<0::8*32>> <>
               <<1::8*32>> <>
               <<2::8*32>> <>
               <<3::8*32>> <>
               <<4::8*32>> <>
               <<5::8*32>> <>
               <<6::8*32>> <>
               <<7::8*32>> <>
               <<8::8*24>> <>
               <<42, 69>>
  end
end
