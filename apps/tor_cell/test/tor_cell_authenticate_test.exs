# SPDX-License-Identifier: ISC

defmodule TorCellAuthenticate do
  use ExUnit.Case
  doctest TorCell.Authenticate

  test "decodes an TorCell.Authenticate cell" do
    auth =
      <<"AUTH0003", 0::8*32, 1::8*32, 2::8*32, 3::8*32, 4::8*32, 5::8*32, 6::8*32, 7::8*32,
        8::8*24, 42, 69>>

    payload = <<3::16, byte_size(auth)::16>> <> auth

    assert TorCell.Authenticate.decode(payload) == %TorCell.Authenticate{
             auth_type: :ed25519_sha256_rfc5705,
             authentication: %TorCell.Authenticate.Ed25519Sha256Rfc5705{
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
           }
  end

  test "encodes an TorCell.Authenticate cell" do
    cell = %TorCell.Authenticate{
      auth_type: :ed25519_sha256_rfc5705,
      authentication: %TorCell.Authenticate.Ed25519Sha256Rfc5705{
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
    }

    auth =
      <<"AUTH0003", 0::8*32, 1::8*32, 2::8*32, 3::8*32, 4::8*32, 5::8*32, 6::8*32, 7::8*32,
        8::8*24, 42, 69>>

    payload = <<3::16, byte_size(auth)::16>> <> auth

    assert TorCell.Authenticate.encode(cell) == payload
  end
end
